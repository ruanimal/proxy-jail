use anyhow::{Context, Result};
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tracing::{debug, info, warn};

use crate::config::JailConfig;
use crate::security;

/// Canonical install path of the bundled tun2socks binary (inside the .deb).
const TUN2SOCKS_DEB_PATH: &str = "/usr/lib/proxy-jail/tun2socks";

/// Only root-owned, non-writable system paths are eligible for root execution.
fn tun2socks_bin() -> Result<PathBuf> {
    if Path::new(TUN2SOCKS_DEB_PATH).exists() {
        return security::trusted_executable(Path::new(TUN2SOCKS_DEB_PATH));
    }
    for path in [
        "/usr/local/bin/tun2socks",
        "/usr/bin/tun2socks",
        "/bin/tun2socks",
    ] {
        if Path::new(path).exists() {
            return security::trusted_executable(Path::new(path));
        }
    }
    anyhow::bail!("Install tun2socks in /usr/local/bin or use the bundled .deb binary")
}

/// Start tun2socks process in the network namespace
pub fn start_tun2socks(jail: &JailConfig, subnet: &str) -> Result<u32> {
    let netns_name = jail.netns_name();
    let pid_file = jail.pid_file();

    // Check if tun2socks is already running
    if let Some(pid) = check_tun2socks_running(jail)? {
        info!("tun2socks already running with PID: {}", pid);
        return Ok(pid);
    }

    // Get gateway for routing
    let gateway = crate::network::get_gateway(subnet)?;

    // "gateway" is a special value written at jail-creation time when the
    // user specifies localhost/127.0.0.1/::1.  It means: resolve to the
    // host's gateway IP at runtime.
    let effective_proxy_host = if jail.proxy.host == "gateway" {
        info!("Proxy host is 'gateway', resolving to {}", gateway);
        gateway.clone()
    } else {
        jail.proxy.host.clone()
    };

    // Resolve on the host before starting the relay: resolving the proxy via
    // the relay would otherwise recursively require the proxy itself. Pass the
    // same IPv4 address to tun2socks and the namespace bypass route.
    let transport_proxy_host = crate::network::resolve_to_ip(&effective_proxy_host)?;

    // Keep credentials out of the startup log.
    let proxy_url = jail.proxy.socks5_url(&transport_proxy_host)?;
    info!(
        "Starting tun2socks in namespace: {} -> {}:{} (resolved {})",
        netns_name, effective_proxy_host, jail.proxy.port, transport_proxy_host
    );

    // Spawn tun2socks via `ip netns exec` (we are already root after the
    // top-level `sudo` re-exec in `main.rs`, so no nested `sudo` is
    // needed here).
    //
    // We use `Command::pre_exec` to call `setsid(2)` in the child right
    // before `execve`.  This detaches tun2socks from proxy-jail's session
    // and process group so that:
    //   - in `jail start`, the daemon survives proxy-jail's exit (reparented
    //     to init instead of dying with the wrapper);
    //   - in `app exec`, signals delivered to the user's app (e.g. Ctrl+C)
    //     do not propagate to tun2socks.
    //
    // `child.id()` is the real tun2socks PID because there is no wrapping
    // process — `ip netns exec` performs an `execve` of tun2socks without
    // forking an intermediate shell.
    //
    // NOTE: tun2socks (Go) requires double-dash for long options.
    let tun2socks = tun2socks_bin()?;

    // Prepare a log file for tun2socks stderr output
    let log_dir = jail.runtime_dir();
    security::private_directory(&log_dir)?;
    let tun2socks_log = log_dir.join("tun2socks.log");
    let log_file = security::private_file(&tun2socks_log, false)?;
    log_file.set_len(0)?;

    let mut cmd = security::command("ip")?;
    cmd.args([
        "netns",
        "exec",
        &netns_name,
        tun2socks.to_str().context("Non-UTF8 tun2socks path")?,
        "--device",
        "tun://tun0",
        "--proxy",
        &proxy_url,
        "--loglevel",
        "info",
    ]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(log_file);

    // Detach the child into its own session before exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn().with_context(|| {
        format!(
            "Failed to start tun2socks at '{}'. Is it installed?",
            tun2socks.display(),
        )
    })?;

    let pid = child.id();

    // Do not publish a PID until device and routes are ready. If any setup
    // step fails, terminate the child so the next start can retry cleanly.
    let setup = (|| -> Result<()> {
        wait_for_device(&netns_name, "tun0", 5000)?;
        if child.try_wait()?.is_some() {
            let stderr = security::read_to_string(&tun2socks_log)
                .unwrap_or_else(|_| "<log file unreadable>".to_string());
            anyhow::bail!(
                "tun2socks died during setup (PID {}). Check log at {}:\n{}",
                pid,
                tun2socks_log.display(),
                stderr,
            );
        }
        crate::network::setup_tun2socks_routing(jail, &transport_proxy_host, &gateway)?;
        security::write(&pid_file, pid.to_string())
            .with_context(|| format!("Failed to write PID file: {:?}", pid_file))?;
        Ok(())
    })();
    if let Err(error) = setup {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(&pid_file);
        return Err(error);
    }
    info!("tun2socks started with PID: {}", pid);
    Ok(pid)
}

/// Check if tun2socks is running for a jail
pub fn check_tun2socks_running(jail: &JailConfig) -> Result<Option<u32>> {
    let pid_file = jail.pid_file();

    if !pid_file.exists() {
        return Ok(None);
    }

    let pid_str = security::read_to_string(&pid_file)
        .with_context(|| format!("Failed to read PID file: {:?}", pid_file))?;

    let pid: u32 = pid_str
        .trim()
        .parse()
        .with_context(|| format!("Invalid PID in file: {}", pid_str))?;

    if is_process_running(pid)? {
        Ok(Some(pid))
    } else {
        // PID file exists but process is dead, clean up
        let _ = fs::remove_file(&pid_file);
        Ok(None)
    }
}

/// Stop tun2socks process
pub fn stop_tun2socks(jail: &JailConfig) -> Result<()> {
    let pid_file = jail.pid_file();

    if let Some(pid) = check_tun2socks_running(jail)? {
        info!("Stopping tun2socks with PID: {}", pid);

        // Send SIGTERM
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }

        // Wait for process to exit
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Force kill if still running
        if is_process_running(pid)? {
            warn!("tun2socks did not stop gracefully, sending SIGKILL");
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
        }

        // Remove PID file
        let _ = fs::remove_file(&pid_file);

        info!("tun2socks stopped");
    } else {
        debug!("tun2socks not running");
    }

    Ok(())
}

/// Wait for a network device to appear in a namespace
fn wait_for_device(netns_name: &str, device: &str, timeout_ms: u64) -> Result<()> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let check_interval = std::time::Duration::from_millis(100);

    loop {
        // proxy-jail is already root; invoking sudo again is unnecessary.
        let output = security::command("ip")?
            .args(["netns", "exec", netns_name, "ip", "link", "show", device])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                debug!("Device {} appeared in namespace {}", device, netns_name);
                return Ok(());
            }
            _ => {}
        }

        if start.elapsed() > timeout {
            anyhow::bail!(
                "Timeout waiting for device {} to appear in namespace {} ({}ms)",
                device,
                netns_name,
                timeout_ms
            );
        }

        std::thread::sleep(check_interval);
    }
}

/// A zombie still has /proc/PID but no longer owns its network device.
fn is_process_running(pid: u32) -> Result<bool> {
    let path = format!("/proc/{pid}/stat");
    match fs::read_to_string(&path) {
        Ok(stat) => process_stat_is_live(&stat),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Failed to inspect {path}")),
    }
}

fn process_stat_is_live(stat: &str) -> Result<bool> {
    let (_, fields) = stat.rsplit_once(')').context("Invalid process stat")?;
    let state = fields
        .split_whitespace()
        .next()
        .context("Missing process state")?;
    Ok(!matches!(state, "Z" | "X" | "x"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zombie_or_dead_process_is_not_running() {
        assert!(process_stat_is_live("42 (tun2socks) S 1").unwrap());
        assert!(!process_stat_is_live("42 (tun2socks) Z 1").unwrap());
        assert!(!process_stat_is_live("42 (name with ) parens) X 1").unwrap());
        assert!(process_stat_is_live("bad stat").is_err());
    }
}
