use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::{debug, info};

use crate::config::JailConfig;

/// Check if a network namespace exists
pub fn netns_exists(name: &str) -> bool {
    let path = format!("/var/run/netns/{}", name);
    Path::new(&path).exists()
}

/// Create the network namespace and veth pair
pub fn create_jail_network(jail: &JailConfig, subnet: &str) -> Result<()> {
    let netns_name = jail.netns_name();
    let veth_host = format!("veth-h-{}", jail.name);
    let veth_ns = format!("veth-n-{}", jail.name);

    // Parse subnet to get IP addresses
    let (network_addr, prefix_len) = parse_subnet(subnet)?;
    let host_ip = format!("{}/{}", increment_ip(&network_addr, 1)?, prefix_len);
    let ns_ip = format!("{}/{}", increment_ip(&network_addr, 2)?, prefix_len);
    let gateway = increment_ip(&network_addr, 1)?;

    info!("Creating network namespace: {}", netns_name);

    // Create network namespace
    run_command("ip", &["netns", "add", &netns_name])?;

    // Create veth pair
    info!("Creating veth pair: {} <-> {}", veth_host, veth_ns);
    run_command("ip", &["link", "add", &veth_host, "type", "veth", "peer", "name", &veth_ns])?;

    // Move veth-ns into namespace
    run_command("ip", &["link", "set", &veth_ns, "netns", &netns_name])?;

    // Configure host side veth
    run_command("ip", &["addr", "add", &host_ip, "dev", &veth_host])?;
    run_command("ip", &["link", "set", &veth_host, "up"])?;

    // Configure namespace side veth
    run_command_in_netns(&netns_name, "ip", &["addr", "add", &ns_ip, "dev", &veth_ns])?;
    run_command_in_netns(&netns_name, "ip", &["link", "set", &veth_ns, "up"])?;
    run_command_in_netns(&netns_name, "ip", &["link", "set", "lo", "up"])?;

    // Set default gateway in namespace
    run_command_in_netns(&netns_name, "ip", &["route", "add", "default", "via", &gateway])?;

    // Set up DNS in namespace (isolated namespace can't reach host's 127.0.0.53)
    // Copy the host's real DNS server into the namespace's resolv.conf
    let netns_resolv_dir = format!("/etc/netns/{}", netns_name);
    std::fs::create_dir_all(&netns_resolv_dir)
        .with_context(|| format!("Failed to create /etc/netns/{}", netns_name))?;
    let dns_content = get_host_dns()?;
    std::fs::write(format!("{}/resolv.conf", netns_resolv_dir), &dns_content)
        .context("Failed to write namespace resolv.conf")?;
    debug!("Namespace DNS config:\n{}", dns_content);

    // Enable IP forwarding on host
    enable_ip_forward()?;

    // Add NAT rule on host
    info!("Adding NAT rule for subnet: {}", subnet);
    run_command(
        "iptables",
        &["-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"],
    )?;

    // Allow forwarding from namespace
    run_command(
        "iptables",
        &[
            "-A", "FORWARD", "-i", &veth_host, "-j", "ACCEPT",
        ],
    )?;
    run_command(
        "iptables",
        &[
            "-A", "FORWARD", "-o", &veth_host, "-j", "ACCEPT",
        ],
    )?;

    info!("Network namespace {} created successfully", netns_name);
    Ok(())
}

/// Destroy the network namespace and clean up
pub fn destroy_jail_network(jail: &JailConfig, subnet: &str) -> Result<()> {
    let netns_name = jail.netns_name();
    let veth_host = format!("veth-h-{}", jail.name);

    info!("Destroying network namespace: {}", netns_name);

    // Remove NAT rule from host
    let _ = run_command(
        "iptables",
        &["-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"],
    );

    // Remove forwarding rules
    let _ = run_command(
        "iptables",
        &["-D", "FORWARD", "-i", &veth_host, "-j", "ACCEPT"],
    );
    let _ = run_command(
        "iptables",
        &["-D", "FORWARD", "-o", &veth_host, "-j", "ACCEPT"],
    );

    // Delete veth pair (deleting one end deletes both)
    let _ = run_command("ip", &["link", "delete", &veth_host]);

    // Delete network namespace
    let _ = run_command("ip", &["netns", "delete", &netns_name]);

    // Clean up /etc/netns/ directory
    let netns_resolv_dir = format!("/etc/netns/{}", netns_name);
    let _ = std::fs::remove_dir_all(&netns_resolv_dir);

    info!("Network namespace {} destroyed", netns_name);
    Ok(())
}

/// Set up routing rules inside the namespace for tun2socks
pub fn setup_tun2socks_routing(
    jail: &JailConfig,
    proxy_host: &str,
    gateway: &str,
) -> Result<()> {
    let netns_name = jail.netns_name();

    // Bring tun0 up (tun2socks creates it but may not set it to UP state)
    info!("Bringing tun0 up");
    run_command_in_netns(
        &netns_name,
        "ip",
        &["link", "set", "tun0", "up"],
    )?;

    // Resolve hostname to IP (ip route requires IP addresses, not hostnames)
    let resolved_host = resolve_to_ip(proxy_host)?;

    // Add route for proxy host to bypass TUN (go through veth)
    // Skip if proxy host is the gateway itself — the connected route on the
    // veth interface already covers it and won't be affected by the default
    // route replacement below.
    if resolved_host != gateway {
        info!("Adding route for proxy host: {} ({}) via {}", proxy_host, resolved_host, gateway);
        run_command_in_netns(
            &netns_name,
            "ip",
            &["route", "add", &resolved_host, "via", gateway],
        )?;
    } else {
        debug!("Proxy host {} is the gateway, skipping explicit route", resolved_host);
    }

    // Replace default route to go through TUN device
    // (the original default route via veth gateway was set during create_jail_network)
    info!("Replacing default route to tun0");
    run_command_in_netns(
        &netns_name,
        "ip",
        &["route", "replace", "default", "dev", "tun0"],
    )?;

    Ok(())
}

/// Get the gateway IP for a subnet (first usable IP)
pub fn get_gateway(subnet: &str) -> Result<String> {
    let (network_addr, _) = parse_subnet(subnet)?;
    increment_ip(&network_addr, 1)
}

/// Get the veth IP inside the network namespace (second usable IP).
/// This is the destination address used when forwarding a host port
/// back into the netns (e.g. by `expose::spawn_forwarder`).
pub fn get_ns_ip(subnet: &str) -> Result<String> {
    let (network_addr, _) = parse_subnet(subnet)?;
    increment_ip(&network_addr, 2)
}

/// Get the host's real DNS server configuration
/// Reads from /run/systemd/resolve/resolv.conf (upstream DNS) or falls back to parsing resolvectl
fn get_host_dns() -> Result<String> {
    // Try systemd-resolved's upstream resolv.conf first (contains real DNS servers, not 127.0.0.53)
    let upstream_path = "/run/systemd/resolve/resolv.conf";
    if let Ok(content) = std::fs::read_to_string(upstream_path) {
        // Filter out 127.0.0.53 (stub) and keep real nameservers
        let filtered: String = content.lines()
            .filter(|line| {
                if line.starts_with("nameserver") {
                    let server = line.split_whitespace().nth(1).unwrap_or("");
                    server != "127.0.0.53"
                } else {
                    true
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        if filtered.contains("nameserver") {
            return Ok(filtered + "\n");
        }
    }

    // Fallback: parse /etc/resolv.conf (skip 127.0.0.53)
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        let filtered: String = content.lines()
            .filter(|line| {
                if line.starts_with("nameserver") {
                    let server = line.split_whitespace().nth(1).unwrap_or("");
                    server != "127.0.0.53"
                } else {
                    !line.is_empty()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        if filtered.contains("nameserver") {
            return Ok(filtered + "\n");
        }
    }

    anyhow::bail!("Failed to detect host DNS server")
}

/// Enable IP forwarding on the host
fn enable_ip_forward() -> Result<()> {
    debug!("Enabling IP forwarding");
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .context("Failed to enable IP forwarding")?;
    Ok(())
}

/// Run a command on the host
fn run_command(program: &str, args: &[&str]) -> Result<()> {
    debug!("Running: {} {}", program, args.join(" "));

    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute: {} {}", program, args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Command failed: {} {}\nStderr: {}",
            program,
            args.join(" "),
            stderr
        );
    }

    Ok(())
}

/// Run a command inside a network namespace
fn run_command_in_netns(netns: &str, program: &str, args: &[&str]) -> Result<()> {
    let mut full_args = vec!["netns", "exec", netns, program];
    full_args.extend_from_slice(args);

    debug!("Running in netns {}: {} {}", netns, program, args.join(" "));

    let output = Command::new("ip")
        .args(&full_args)
        .output()
        .with_context(|| format!("Failed to execute in netns {}: {} {}", netns, program, args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Command failed in netns {}: {} {}\nStderr: {}",
            netns,
            program,
            args.join(" "),
            stderr
        );
    }

    Ok(())
}

/// Resolve a hostname to an IP address
fn resolve_to_ip(host: &str) -> Result<String> {
    // Already an IP address?
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(host.to_string());
    }

    // Resolve via DNS
    use std::net::ToSocketAddrs;
    let addr = format!("{}:0", host);
    let mut addrs = addr.to_socket_addrs()
        .with_context(|| format!("Failed to resolve hostname: {}", host))?;

    addrs.next()
        .map(|a| a.ip().to_string())
        .ok_or_else(|| anyhow::anyhow!("No addresses found for hostname: {}", host))
}

/// Parse a subnet string (e.g., "10.10.0.0/24") into network address and prefix length
fn parse_subnet(subnet: &str) -> Result<(String, u8)> {
    let parts: Vec<&str> = subnet.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid subnet format: {}", subnet);
    }

    let addr = parts[0].to_string();
    let prefix: u8 = parts[1]
        .parse()
        .with_context(|| format!("Invalid prefix length: {}", parts[1]))?;

    if prefix > 32 {
        anyhow::bail!("Invalid prefix length: {}", prefix);
    }

    Ok((addr, prefix))
}

/// Increment an IP address by a given amount
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

    #[test]
    fn test_parse_subnet() {
        let (addr, prefix) = parse_subnet("10.10.0.0/24").unwrap();
        assert_eq!(addr, "10.10.0.0");
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_increment_ip() {
        assert_eq!(increment_ip("10.10.0.0", 1).unwrap(), "10.10.0.1");
        assert_eq!(increment_ip("10.10.0.0", 2).unwrap(), "10.10.0.2");
        assert_eq!(increment_ip("10.10.0.255", 1).unwrap(), "10.10.1.0");
    }

    #[test]
    fn test_get_gateway() {
        assert_eq!(get_gateway("10.10.0.0/24").unwrap(), "10.10.0.1");
        assert_eq!(get_gateway("10.10.1.0/24").unwrap(), "10.10.1.1");
        assert_eq!(get_gateway("10.203.240.0/30").unwrap(), "10.203.240.1");
        assert_eq!(get_gateway("10.203.240.4/30").unwrap(), "10.203.240.5");
    }

    #[test]
    fn test_get_ns_ip_for_30_subnets() {
        assert_eq!(get_ns_ip("10.203.240.0/30").unwrap(), "10.203.240.2");
        assert_eq!(get_ns_ip("10.203.240.4/30").unwrap(), "10.203.240.6");
        assert_eq!(get_ns_ip("10.203.240.252/30").unwrap(), "10.203.240.254");
    }
}
