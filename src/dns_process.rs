//! Lifecycle management for the per-jail loopback DNS relay.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::config::JailConfig;
use crate::security;

#[derive(Debug, Serialize, Deserialize)]
struct RelayRecord {
    pid: u32,
    start_time: u64,
    netns_inode: u64,
    upstreams: Vec<Ipv4Addr>,
}

fn record_path(jail: &JailConfig) -> PathBuf {
    jail.runtime_dir().join("dns-relay.json")
}

fn process_start_time(pid: u32) -> Result<(u64, bool)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, tail) = stat.rsplit_once(')').context("Invalid process stat")?;
    let fields: Vec<_> = tail.split_whitespace().collect();
    ensure!(fields.len() > 19, "Invalid process stat");
    Ok((fields[19].parse()?, fields[0] == "Z"))
}

fn is_record_alive(jail: &JailConfig, record: &RelayRecord) -> bool {
    let proc = PathBuf::from(format!("/proc/{}", record.pid));
    let Ok((start_time, zombie)) = process_start_time(record.pid) else {
        return false;
    };
    if zombie || start_time != record.start_time {
        return false;
    }
    let Ok(ns) = fs::metadata(proc.join("ns/net")) else {
        return false;
    };
    let Ok(named_ns) = fs::metadata(format!("/var/run/netns/{}", jail.netns_name())) else {
        return false;
    };
    if ns.ino() != record.netns_inode || ns.ino() != named_ns.ino() {
        return false;
    }
    let Ok(status) = fs::read_to_string(proc.join("status")) else {
        return false;
    };
    if !status.lines().any(|line| {
        line.strip_prefix("Uid:")
            .and_then(|value| value.split_whitespace().next())
            == Some("65534")
    }) {
        return false;
    }
    let Ok(args) = fs::read(proc.join("cmdline")) else {
        return false;
    };
    let args: Vec<_> = args
        .split(|b| *b == 0)
        .filter(|arg| !arg.is_empty())
        .collect();
    args.iter().any(|arg| *arg == b"__dns-relay")
}

fn read_record(jail: &JailConfig) -> Result<Option<RelayRecord>> {
    let path = record_path(jail);
    match security::read(&path) {
        Ok(data) => Ok(Some(serde_json::from_slice(&data).with_context(|| {
            format!("Invalid DNS relay record: {}", path.display())
        })?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Cannot read {}", path.display())),
    }
}

/// Avoid sending DNS to the physical network via a more specific bypass route.
fn validate_upstream_routes(jail: &JailConfig, upstreams: &[Ipv4Addr]) -> Result<()> {
    for server in upstreams {
        let output = security::command("ip")?
            .args([
                "netns",
                "exec",
                &jail.netns_name(),
                "ip",
                "-j",
                "-4",
                "route",
                "get",
                &server.to_string(),
            ])
            .output()
            .with_context(|| format!("Failed to inspect route to DNS server {server}"))?;
        ensure!(
            output.status.success(),
            "Cannot route DNS server {server}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let routes: Vec<serde_json::Value> =
            serde_json::from_slice(&output.stdout).context("Failed to parse DNS route")?;
        ensure!(
            routes
                .first()
                .and_then(|route| route.get("dev"))
                .and_then(|dev| dev.as_str())
                == Some("tun0"),
            "DNS server {server} does not route through tun0 in jail '{}'",
            jail.name
        );
    }
    Ok(())
}

/// Stop only a relay whose PID, start time, network namespace and identity match.
pub fn stop(jail: &JailConfig) -> Result<()> {
    let Some(record) = read_record(jail)? else {
        return Ok(());
    };
    if is_record_alive(jail, &record) {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(record.pid as i32),
            nix::sys::signal::Signal::SIGTERM,
        )
        .context("Failed to stop DNS relay")?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while is_record_alive(jail, &record) {
            ensure!(
                Instant::now() < deadline,
                "DNS relay did not stop; retry jail stop"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    match fs::remove_file(record_path(jail)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("Failed to remove DNS relay record"),
    }
}

/// Ensure a ready local relay for the current upstreams, then publish its resolver file.
/// The caller must hold the jail lock and start tun2socks first.
pub fn ensure_ready(jail: &JailConfig) -> Result<()> {
    jail.validate_dns()?;
    if let Some(record) = read_record(jail)? {
        // If a former bypass route changed, stop the old relay before it can
        // continue forwarding queries outside the TUN.
        if is_record_alive(jail, &record)
            && validate_upstream_routes(jail, &record.upstreams).is_err()
        {
            stop(jail)?;
        }
    }
    validate_upstream_routes(jail, jail.effective_dns_servers())?;
    if let Some(record) = read_record(jail)? {
        if is_record_alive(jail, &record) && record.upstreams == jail.effective_dns_servers() {
            crate::network::sync_jail_dns(jail)?;
            return Ok(());
        }
        stop(jail)?;
    }

    let runtime = jail.runtime_dir();
    security::private_directory(&runtime)?;
    let log_path = runtime.join("dns-relay.log");
    let log = security::private_file(&log_path, true)?;
    let executable = std::env::current_exe().context("Failed to locate proxy-jail executable")?;
    let mut cmd = security::command("ip")?;
    cmd.args(["netns", "exec", &jail.netns_name()])
        .arg(executable)
        .arg("__dns-relay")
        .arg("--parent")
        .arg(std::process::id().to_string());
    for server in jail.effective_dns_servers() {
        cmd.arg("--upstream").arg(server.to_string());
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(log));
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("Failed to start DNS relay")?;
    let stdout = child
        .stdout
        .take()
        .context("Missing DNS relay readiness pipe")?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        for _ in 0..2 {
            let mut line = String::new();
            let result = reader.read_line(&mut line).map(|_| line);
            if sender.send(result).is_err() {
                break;
            }
        }
    });
    let ready = receiver.recv_timeout(Duration::from_secs(5));
    if !matches!(ready, Ok(Ok(ref line)) if line.trim() == "READY") {
        let _ = child.kill();
        let _ = child.wait();
        bail!("DNS relay failed to start; check {}", log_path.display());
    }
    let pid = child.id();
    let recorded = (|| -> Result<RelayRecord> {
        let (start_time, zombie) = process_start_time(pid)?;
        ensure!(!zombie, "DNS relay exited during startup");
        let netns_inode = fs::metadata(format!("/var/run/netns/{}", jail.netns_name()))?.ino();
        let record = RelayRecord {
            pid,
            start_time,
            netns_inode,
            upstreams: jail.effective_dns_servers().to_vec(),
        };
        ensure!(
            is_record_alive(jail, &record),
            "DNS relay identity check failed"
        );
        Ok(record)
    })();
    let record = match recorded {
        Ok(record) => record,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    // Write to a new file, then rename it into place: an interrupted manager
    // must not leave a truncated record blocking recovery.
    let path = record_path(jail);
    let temporary = runtime.join(format!("dns-relay-{pid}.tmp"));
    let registration = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .context("Failed to create DNS relay record")?;
        file.write_all(&serde_json::to_vec(&record)?)?;
        fs::rename(&temporary, &path).context("Failed to register DNS relay")?;
        child
            .stdin
            .take()
            .context("Missing DNS relay acknowledgement pipe")?
            .write_all(b"1")?;
        match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(line)) if line.trim() == "ARMED" => Ok(()),
            _ => bail!("DNS relay failed to complete registration"),
        }
    })();
    if let Err(error) = registration {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(&temporary);
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    crate::network::sync_jail_dns(jail)?;
    Ok(())
}
