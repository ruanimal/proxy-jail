use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::{debug, info, warn};

use crate::config::JailConfig;

/// tun2socks configuration structure (JSON format for xjasonlyu/tun2socks)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tun2SocksConfig {
    /// TUN device settings
    pub tun: TunDevice,

    /// SOCKS5 proxy settings
    pub proxy: ProxySettings,
}

/// TUN device configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunDevice {
    /// TUN device name
    pub name: String,

    /// TUN device IP address (CIDR notation)
    pub addr: String,

    /// TUN device gateway
    pub gateway: String,

    /// MTU size
    pub mtu: u16,
}

/// SOCKS5 proxy settings for tun2socks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySettings {
    /// SOCKS5 server address (host:port)
    pub server: String,

    /// Optional username
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Optional password
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// Generate tun2socks configuration file
pub fn generate_tun2socks_config(jail: &JailConfig, subnet: &str) -> Result<()> {
    let runtime_dir = jail.runtime_dir();

    // Create runtime directory if it doesn't exist
    fs::create_dir_all(&runtime_dir)
        .with_context(|| format!("Failed to create runtime directory: {:?}", runtime_dir))?;

    // Parse subnet to get TUN device IP
    let (network_addr, prefix_len) = parse_subnet(subnet)?;
    let tun_ip = increment_ip(&network_addr, 10)?; // Use .10 for TUN device
    let tun_gateway = increment_ip(&network_addr, 2)?; // Use .2 for gateway (namespace veth)

    let config = Tun2SocksConfig {
        tun: TunDevice {
            name: "tun0".to_string(),
            addr: format!("{}/{}", tun_ip, prefix_len),
            gateway: tun_gateway,
            mtu: 9000,
        },
        proxy: ProxySettings {
            server: jail.proxy.socks5_addr(),
            username: jail.proxy.auth.as_ref().map(|a| a.username.clone()),
            password: jail.proxy.auth.as_ref().map(|a| a.password.clone()),
        },
    };

    let config_path = jail.tun2socks_config_file();
    let config_json = serde_json::to_string_pretty(&config)
        .context("Failed to serialize tun2socks config")?;

    fs::write(&config_path, config_json)
        .with_context(|| format!("Failed to write tun2socks config: {:?}", config_path))?;

    debug!("Generated tun2socks config: {:?}", config_path);
    Ok(())
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
    let child = Command::new("ip")
        .args(&[
            "netns", "exec", &netns_name,
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
        // Check if device exists in namespace
        let output = Command::new("ip")
            .args(&["netns", "exec", netns_name, "ip", "link", "show", device])
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

/// Parse a subnet string
fn parse_subnet(subnet: &str) -> Result<(String, u8)> {
    let parts: Vec<&str> = subnet.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid subnet format: {}", subnet);
    }

    let addr = parts[0].to_string();
    let prefix: u8 = parts[1]
        .parse()
        .with_context(|| format!("Invalid prefix length: {}", parts[1]))?;

    Ok((addr, prefix))
}

/// Increment an IP address
fn increment_ip(ip: &str, amount: u8) -> Result<String> {
    let parts: Vec<u8> = ip
        .split('.')
        .map(|p| p.parse::<u8>())
        .collect::<std::result::Result<Vec<u8>, _>>()
        .with_context(|| format!("Invalid IP address: {}", ip))?;

    if parts.len() != 4 {
        anyhow::bail!("Invalid IP address: {}", ip);
    }

    let mut result = parts.clone();
    let mut carry = amount as u16;

    for i in (0..4).rev() {
        let sum = result[i] as u16 + carry;
        result[i] = (sum % 256) as u8;
        carry = sum / 256;
    }

    if carry > 0 {
        anyhow::bail!("IP address overflow");
    }

    Ok(format!("{}.{}.{}.{}", result[0], result[1], result[2], result[3]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyConfig, ProxyAuth};

    #[test]
    fn test_generate_config() {
        let jail = JailConfig {
            name: "test".to_string(),
            proxy: ProxyConfig {
                host: "127.0.0.1".to_string(),
                port: 1080,
                proxy_type: "socks5".to_string(),
                auth: Some(ProxyAuth {
                    username: "user".to_string(),
                    password: "pass".to_string(),
                }),
            },
            apps: vec![],
            subnet: None,
        };

        let config = Tun2SocksConfig {
            tun: TunDevice {
                name: "tun0".to_string(),
                addr: "10.10.0.10/24".to_string(),
                gateway: "10.10.0.2".to_string(),
                mtu: 9000,
            },
            proxy: ProxySettings {
                server: "127.0.0.1:1080".to_string(),
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
            },
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("tun0"));
        assert!(json.contains("127.0.0.1:1080"));
        assert!(json.contains("user"));
    }
}
