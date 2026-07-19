use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::{debug, info, warn};

use crate::config::JailConfig;

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

    // If proxy host is localhost/127.0.0.1, use the gateway IP instead.
    // Inside the namespace, 127.0.0.1 refers to the namespace's own loopback,
    // not the host's. The gateway IP (host veth) routes to the host where the
    // proxy actually listens.
    let effective_proxy_host = if jail.proxy.host == "localhost"
        || jail.proxy.host == "127.0.0.1"
        || jail.proxy.host == "::1"
    {
        info!(
            "Proxy host is {}, using gateway {} as proxy address",
            jail.proxy.host, gateway
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

    // Start tun2socks using command-line arguments (more reliable than config file)
    // Use sudo since we're no longer running as root (the program runs as the
    // real user and only elevates for privileged operations).
    let child = Command::new("sudo")
        .args(&[
            "ip", "netns", "exec", &netns_name,
            "tun2socks",
            "-device", "tun://tun0",
            "-proxy", &proxy_url,
            "-loglevel", "info",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to start tun2socks. Is it installed?")?;

    let pid = child.id();

    // Wait for tun0 device to appear (tun2socks needs time to create it)
    wait_for_device(&netns_name, "tun0", 5000)?;

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


