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

    // Add route for proxy host to bypass TUN (go through veth)
    info!("Adding route for proxy host: {} via {}", proxy_host, gateway);
    run_command_in_netns(
        &netns_name,
        "ip",
        &["route", "add", proxy_host, "via", gateway],
    )?;

    // Set default route to TUN device
    info!("Setting default route to tun0");
    run_command_in_netns(
        &netns_name,
        "ip",
        &["route", "add", "default", "dev", "tun0"],
    )?;

    Ok(())
}

/// Get the gateway IP for a subnet (first usable IP)
pub fn get_gateway(subnet: &str) -> Result<String> {
    let (network_addr, _) = parse_subnet(subnet)?;
    increment_ip(&network_addr, 1)
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
    }
}
