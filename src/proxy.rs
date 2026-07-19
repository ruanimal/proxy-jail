use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::{debug, info, warn};

use crate::config::JailConfig;

/// Canonical install path of the bundled tun2socks binary (inside the .deb).
const TUN2SOCKS_DEB_PATH: &str = "/usr/lib/proxy-jail/tun2socks";

/// Resolve the path to the tun2socks binary.
///
/// If the binary was installed via .deb, prefer that path.  Otherwise fall
/// back to `tun2socks` on `$PATH` (works for manual installs / `cargo build`).
fn tun2socks_bin() -> &'static str {
    if Path::new(TUN2SOCKS_DEB_PATH).exists() {
        TUN2SOCKS_DEB_PATH
    } else {
        "tun2socks"
    }
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
        info!(
            "Proxy host is 'gateway', resolving to {}",
            gateway
        );
        gateway.clone()
    } else {
        jail.proxy.host.clone()
    };

    // Build proxy URL
    let proxy_url = match &jail.proxy.auth {
        Some(auth) => format!("socks5://{}:{}@{}:{}", auth.username, auth.password, effective_proxy_host, jail.proxy.port),
        None => format!("socks5://{}:{}", effective_proxy_host, jail.proxy.port),
    };

    info!("Starting tun2socks in namespace: {} -> {}", netns_name, proxy_url);

    // Start tun2socks using command-line arguments (more reliable than config file).
    // Runs inside the namespace as root (via sudo ip netns exec), so no
    // setcap is needed on the tun2socks binary itself.
    //
    // IMPORTANT: We use `setsid` to fully detach tun2socks from the parent
    // process group.  Without this, tun2socks (a Go program) can receive
    // unexpected signals when the Rust `Child` handle is dropped or when
    // the proxy-jail process exits, causing it to become a zombie.
    //
    // NOTE: tun2socks (Go) requires double-dash for long options.
    let tun2socks = tun2socks_bin();

    // Prepare a log file for tun2socks stderr output
    let log_dir = jail.runtime_dir();
    fs::create_dir_all(&log_dir)
        .with_context(|| format!("Failed to create log directory: {:?}", log_dir))?;
    let tun2socks_log = log_dir.join("tun2socks.log");
    let log_file = fs::File::create(&tun2socks_log)
        .with_context(|| format!("Failed to create tun2socks log file: {:?}", tun2socks_log))?;

    let child = Command::new("sudo")
        .args(&[
            "setsid",
            "ip", "netns", "exec", &netns_name,
            tun2socks,
            "--device", "tun://tun0",
            "--proxy", &proxy_url,
            "--loglevel", "info",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
        .with_context(|| {
            format!(
                "Failed to start tun2socks at '{}'. Is it installed?",
                tun2socks,
            )
        })?;

    let child_pid = child.id();

    // Give tun2socks a moment to start, then check if the spawn succeeded.
    // With `setsid`, the sudo wrapper may exit quickly (setsid forks), so
    // we check for the actual tun2socks process instead.
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Wait for tun0 device to appear (tun2socks needs time to create it)
    wait_for_device(&netns_name, "tun0", 5000)?;

    // Find the actual tun2socks PID.  With `setsid`, child.id() is the
    // sudo wrapper which may have already exited.  Scan /proc for the
    // tun2socks binary running in our network namespace.
    let tun2socks_pid = find_tun2socks_pid(&netns_name)
        .or_else(|| {
            // Fallback: check if the original child PID is still alive
            // (happens when setsid is not available)
            if is_process_running(child_pid).unwrap_or(false) {
                Some(child_pid)
            } else {
                None
            }
        });

    let pid = match tun2socks_pid {
        Some(p) => p,
        None => {
            let stderr = fs::read_to_string(&tun2socks_log)
                .unwrap_or_else(|_| "<log file unreadable>".to_string());
            anyhow::bail!(
                "tun2socks process not found after startup. Check log at {}:\n{}",
                tun2socks_log.display(),
                stderr,
            );
        }
    };

    // Verify tun2socks is still alive after device setup
    if !is_process_running(pid)? {
        let stderr = fs::read_to_string(&tun2socks_log)
            .unwrap_or_else(|_| "<log file unreadable>".to_string());
        anyhow::bail!(
            "tun2socks died during setup (PID {}). Check log at {}:\n{}",
            pid,
            tun2socks_log.display(),
            stderr,
        );
    }

    // Write PID file
    fs::write(&pid_file, pid.to_string())
        .with_context(|| format!("Failed to write PID file: {:?}", pid_file))?;

    // Set up routing rules
    // Use effective_proxy_host for routing too (localhost → gateway)
    crate::network::setup_tun2socks_routing(jail, &effective_proxy_host, &gateway)?;

    info!("tun2socks started with PID: {}", pid);
    Ok(pid)
}

/// Check if tun2socks is running for a jail
pub fn check_tun2socks_running(jail: &JailConfig) -> Result<Option<u32>> {
    let pid_file = jail.pid_file();

    if !pid_file.exists() {
        return Ok(None);
    }

    let pid_str = fs::read_to_string(&pid_file)
        .with_context(|| format!("Failed to read PID file: {:?}", pid_file))?;

    let pid: u32 = pid_str.trim().parse()
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
        // Check if device exists in namespace (needs sudo for netns access)
        let output = Command::new("sudo")
            .args(&["ip", "netns", "exec", netns_name, "ip", "link", "show", device])
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
                device, netns_name, timeout_ms
            );
        }

        std::thread::sleep(check_interval);
    }
}

/// Check if a process is running
fn is_process_running(pid: u32) -> Result<bool> {
    let proc_path = format!("/proc/{}", pid);
    Ok(Path::new(&proc_path).exists())
}

/// Find the PID of a `tun2socks` process running inside the given network
/// namespace.  Scans `/proc` for processes whose `/proc/<pid>/comm` is
/// "tun2socks" and whose network namespace matches `netns_name`.
///
/// Returns `None` if no matching process is found.
fn find_tun2socks_pid(netns_name: &str) -> Option<u32> {
    // Get the inode of the target network namespace
    let target_inode = netns_inode(netns_name)?;

    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Check if this process is "tun2socks"
        let comm = match std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if comm.trim() != "tun2socks" {
            continue;
        }

        // Check if it's in the target network namespace
        let ns_link = match std::fs::read_link(format!("/proc/{}/ns/net", pid)) {
            Ok(l) => l,
            Err(_) => continue,
        };
        let ns_str = ns_link.to_string_lossy();
        // ns_str looks like "net:[<inode>]"
        let inode_str = ns_str.trim_start_matches("net:[").trim_end_matches(']');
        if inode_str == target_inode.to_string() {
            return Some(pid);
        }
    }
    None
}

/// Get the inode number of a network namespace by name.
fn netns_inode(netns_name: &str) -> Option<u64> {
    let output = Command::new("sudo")
        .args(["ip", "netns", "exec", netns_name, "readlink", "/proc/self/ns/net"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout);
    let s = s.trim().trim_start_matches("net:[").trim_end_matches(']');
    s.parse().ok()
}


