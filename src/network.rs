use anyhow::{Context, Result};
use std::path::Path;
use tracing::{debug, info};

use crate::config::JailConfig;
use crate::security;

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

    // Validate before creating network resources. DNS is published only
    // after the TUN route and loopback relay are ready.
    jail.validate_dns()?;

    info!("Creating network namespace: {}", netns_name);

    // Create network namespace
    run_command("ip", &["netns", "add", &netns_name])?;

    // Create veth pair
    info!("Creating veth pair: {} <-> {}", veth_host, veth_ns);
    run_command(
        "ip",
        &[
            "link", "add", &veth_host, "type", "veth", "peer", "name", &veth_ns,
        ],
    )?;

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
    run_command_in_netns(
        &netns_name,
        "ip",
        &["route", "add", "default", "via", &gateway],
    )?;

    // Enable IP forwarding on host
    enable_ip_forward()?;

    // Add NAT rule on host
    info!("Adding NAT rule for subnet: {}", subnet);
    run_command(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            subnet,
            "-j",
            "MASQUERADE",
        ],
    )?;

    // Allow forwarding from namespace
    run_command(
        "iptables",
        &["-A", "FORWARD", "-i", &veth_host, "-j", "ACCEPT"],
    )?;
    run_command(
        "iptables",
        &["-A", "FORWARD", "-o", &veth_host, "-j", "ACCEPT"],
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
        &[
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            subnet,
            "-j",
            "MASQUERADE",
        ],
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
pub fn setup_tun2socks_routing(jail: &JailConfig, proxy_host: &str, gateway: &str) -> Result<()> {
    let netns_name = jail.netns_name();

    // Bring tun0 up (tun2socks creates it but may not set it to UP state)
    info!("Bringing tun0 up");
    run_command_in_netns(&netns_name, "ip", &["link", "set", "tun0", "up"])?;

    // Resolve hostname to IP (ip route requires IP addresses, not hostnames)
    let resolved_host = resolve_to_ip(proxy_host)?;

    // Replace the proxy bypass route so recovery after a tun2socks restart is idempotent.
    // Skip if proxy host is the gateway itself — the connected route on the
    // veth interface already covers it and won't be affected by the default
    // route replacement below.
    if resolved_host != gateway {
        info!(
            "Setting route for proxy host: {} ({}) via {}",
            proxy_host, resolved_host, gateway
        );
        run_command_in_netns(
            &netns_name,
            "ip",
            &["route", "replace", &resolved_host, "via", gateway],
        )?;
    } else {
        debug!(
            "Proxy host {} is the gateway, skipping explicit route",
            resolved_host
        );
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

/// Build a resolver configuration independent of the host's physical network.
fn jail_dns_config(jail: &JailConfig) -> Result<String> {
    jail.validate_dns()?;
    let mut content = String::new();
    content.push_str("nameserver 127.0.0.1\n");
    if !jail.dns_search.is_empty() {
        content.push_str(&format!("search {}\n", jail.dns_search.join(" ")));
    }
    // glibc uses TCP to the local relay. Other clients can use UDP.
    content.push_str("options use-vc\n");
    Ok(content)
}

/// Refresh DNS without recreating the netns or restarting its processes.
/// Returns whether the managed resolver configuration changed.
pub fn sync_jail_dns(jail: &JailConfig) -> Result<bool> {
    let content = jail_dns_config(jail)?;
    let path = Path::new("/etc/netns")
        .join(jail.netns_name())
        .join("resolv.conf");
    let changed = write_jail_dns(&path, &content)?;
    if changed {
        debug!("Updated jail DNS to use local relay: {}", path.display());
    }
    Ok(changed)
}

fn write_jail_dns(path: &Path, content: &str) -> Result<bool> {
    let parent = path
        .parent()
        .context("DNS configuration path has no parent")?;
    security::directory(parent, true, 0o755)
        .with_context(|| format!("Failed to create {}", parent.display()))?;
    if security::read(path).is_ok_and(|existing| existing == content.as_bytes()) {
        return Ok(false);
    }

    // Keep the inode: ip netns exec bind-mounts this file as /etc/resolv.conf
    // for each process. An atomic rename would leave running applications
    // bound to the old DNS configuration instead of updating them.
    security::write_public(path, content)
        .with_context(|| format!("Failed to write jail DNS configuration: {}", path.display()))?;
    Ok(true)
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

    let output = security::command(program)?
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

    let output = security::command("ip")?
        .args(&full_args)
        .output()
        .with_context(|| {
            format!(
                "Failed to execute in netns {}: {} {}",
                netns,
                program,
                args.join(" ")
            )
        })?;

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

/// Resolve the SOCKS5 endpoint on the host before the jail DNS relay starts.
/// The jail's IPv4 bypass route and tun2socks must use the same address.
pub fn resolve_to_ip(host: &str) -> Result<String> {
    use std::net::{Ipv4Addr, ToSocketAddrs};
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip.to_string());
    }
    let addr = format!("{}:0", host);
    addr.to_socket_addrs()
        .with_context(|| format!("Failed to resolve hostname: {}", host))?
        .find(|address| address.is_ipv4())
        .map(|address| address.ip().to_string())
        .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for hostname: {}", host))
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

    Ok(format!(
        "{}.{}.{}.{}",
        result[0], result[1], result[2], result[3]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    const DEFAULT_DNS_CONFIG: &str = "nameserver 127.0.0.1\noptions use-vc\n";

    fn dns_jail() -> JailConfig {
        serde_yaml::from_str("name: test\nproxy: {host: gateway, port: 1080}\n").unwrap()
    }

    struct DnsTestDir(PathBuf);

    impl DnsTestDir {
        fn new() -> Self {
            let base = std::env::var_os("PI_SCRATCH_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let path = base.join(format!(
                "proxy-jail-dns-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn resolv_conf(&self) -> PathBuf {
            self.0.join("pj-test/resolv.conf")
        }
    }

    impl Drop for DnsTestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_jail_dns_uses_local_relay_and_tcp() {
        let directory = DnsTestDir::new();
        let path = directory.resolv_conf();
        let content = jail_dns_config(&dns_jail()).unwrap();
        assert!(write_jail_dns(&path, &content).unwrap());
        assert_eq!(std::fs::read_to_string(path).unwrap(), DEFAULT_DNS_CONFIG);
    }

    #[test]
    fn test_jail_dns_refresh_preserves_existing_bindings() {
        let directory = DnsTestDir::new();
        let path = directory.resolv_conf();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "nameserver 192.168.10.1\nnameserver 2408:8248:800:e1a0::1\nsearch old.lan\n",
        )
        .unwrap();

        // An open descriptor observes the same inode, like a bind mount,
        // without introducing a hard link that privileged writes must reject.
        let mut bound_file = std::fs::File::open(&path).unwrap();
        let old_inode = std::fs::metadata(&path).unwrap().ino();

        let content = jail_dns_config(&dns_jail()).unwrap();
        assert!(write_jail_dns(&path, &content).unwrap());
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), old_inode);
        let mut observed = String::new();
        std::io::Read::read_to_string(&mut bound_file, &mut observed).unwrap();
        assert_eq!(observed, content);
    }

    #[test]
    fn test_jail_dns_refresh_is_a_noop_when_unchanged() {
        let directory = DnsTestDir::new();
        let path = directory.resolv_conf();
        let content = jail_dns_config(&dns_jail()).unwrap();
        assert!(write_jail_dns(&path, &content).unwrap());
        let original = std::fs::metadata(&path).unwrap();

        assert!(!write_jail_dns(&path, &content).unwrap());
        let unchanged = std::fs::metadata(&path).unwrap();
        assert_eq!(unchanged.ino(), original.ino());
        assert_eq!(unchanged.modified().unwrap(), original.modified().unwrap());
    }

    #[test]
    fn test_jail_dns_refresh_reports_write_failures() {
        let directory = DnsTestDir::new();
        let path = directory.resolv_conf();
        std::fs::create_dir_all(&path).unwrap();
        let error = write_jail_dns(&path, DEFAULT_DNS_CONFIG).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Failed to write jail DNS configuration")
        );
    }

    #[test]
    fn test_private_dns_and_search_domains_are_per_jail() {
        let mut jail = dns_jail();
        jail.dns_servers = Some(vec![Ipv4Addr::new(10, 88, 0, 53)]);
        jail.dns_search = vec!["corp.example".to_string(), "lab.corp.example".to_string()];
        assert_eq!(
            jail_dns_config(&jail).unwrap(),
            "nameserver 127.0.0.1\nsearch corp.example lab.corp.example\noptions use-vc\n"
        );
        assert_eq!(jail_dns_config(&dns_jail()).unwrap(), DEFAULT_DNS_CONFIG);

        let yaml = serde_yaml::to_string(&jail).unwrap();
        let reloaded: JailConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            jail_dns_config(&reloaded).unwrap(),
            jail_dns_config(&jail).unwrap()
        );
    }

    #[test]
    fn test_invalid_jail_dns_configuration_is_rejected() {
        let mut jail = dns_jail();
        jail.dns_servers = Some(Vec::new());
        assert!(jail_dns_config(&jail).is_err());
        for server in ["0.0.0.0", "127.0.0.53", "224.0.0.1", "255.255.255.255"] {
            jail.dns_servers = Some(vec![server.parse().unwrap()]);
            assert!(
                jail_dns_config(&jail).is_err(),
                "accepted DNS server {server}"
            );
        }
        jail.dns_servers = None;
        for domain in [
            "",
            "corp..example",
            "corp example",
            "corp\nnameserver 127.0.0.1",
        ] {
            jail.dns_search = vec![domain.to_string()];
            assert!(
                jail_dns_config(&jail).is_err(),
                "accepted search domain {domain:?}"
            );
        }
    }

    #[test]
    fn test_resolve_proxy_endpoint_as_ipv4_before_relay_starts() {
        assert_eq!(resolve_to_ip("10.126.126.2").unwrap(), "10.126.126.2");
        assert_eq!(resolve_to_ip("localhost").unwrap(), "127.0.0.1");
        assert!(resolve_to_ip("::1").is_err());
    }

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
