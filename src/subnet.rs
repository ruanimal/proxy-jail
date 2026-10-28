use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::process::Command;

/// An uncommon RFC 1918 pool; only individual /30 routes are installed.
pub const DEFAULT_POOL: &str = "10.203.240.0/20";
const JAIL_PREFIX: u8 = 30;
const JAIL_SIZE: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Subnet {
    first: u32,
    last: u32,
}

impl Ipv4Subnet {
    pub fn parse(cidr: &str) -> Result<Self> {
        let (address, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
        let address: Ipv4Addr = address
            .parse()
            .with_context(|| format!("Invalid IPv4 address: {address}"))?;
        let prefix: u8 = prefix
            .parse()
            .with_context(|| format!("Invalid IPv4 prefix: {cidr}"))?;
        ensure!(prefix <= 32, "Invalid IPv4 prefix: {cidr}");
        let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
        let first = u32::from(address) & mask;
        Ok(Self {
            first,
            last: first | !mask,
        })
    }

    fn overlaps(self, other: Self) -> bool {
        self.first <= other.last && other.first <= self.last
    }
}

/// Allocate the ordinal free /30, avoiding whole CIDR ranges, not just IPs.
pub fn allocate(occupied: &[Ipv4Subnet], ordinal: usize) -> Result<String> {
    let pool = Ipv4Subnet::parse(DEFAULT_POOL)?;
    (pool.first..=pool.last)
        .step_by(JAIL_SIZE)
        .filter(|first| {
            let candidate = Ipv4Subnet {
                first: *first,
                last: *first + JAIL_SIZE as u32 - 1,
            };
            !occupied.iter().any(|subnet| candidate.overlaps(*subnet))
        })
        .nth(ordinal)
        .map(|first| format!("{}/{JAIL_PREFIX}", Ipv4Addr::from(first)))
        .with_context(|| {
            format!(
                "No free /{JAIL_PREFIX} subnet in {DEFAULT_POOL}; \
                 set an explicit non-overlapping subnet in the jail configuration"
            )
        })
}

/// Include all routing tables so LAN, container and policy/VPN routes count.
pub fn host_ipv4_subnets() -> Result<Vec<Ipv4Subnet>> {
    let output = Command::new("ip")
        .args(["-j", "-4", "route", "show", "table", "all"])
        .output()
        .context("Failed to inspect host IPv4 routes")?;
    ensure!(
        output.status.success(),
        "Failed to inspect host IPv4 routes: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    parse_routes(&output.stdout)
}

fn parse_routes(json: &[u8]) -> Result<Vec<Ipv4Subnet>> {
    #[derive(Deserialize)]
    struct Route {
        dst: Option<String>,
    }

    let routes: Vec<Route> =
        serde_json::from_slice(json).context("Failed to parse host IPv4 routes")?;
    routes
        .into_iter()
        .filter_map(|route| route.dst)
        // A default route provides connectivity; it does not reserve every IP.
        .filter(|dst| dst != "default" && dst != "0.0.0.0/0")
        .map(|dst| Ipv4Subnet::parse(&dst))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_consecutive_30s_and_rolls_over_octets() {
        assert_eq!(allocate(&[], 0).unwrap(), "10.203.240.0/30");
        assert_eq!(allocate(&[], 1).unwrap(), "10.203.240.4/30");
        assert_eq!(allocate(&[], 63).unwrap(), "10.203.240.252/30");
        assert_eq!(allocate(&[], 64).unwrap(), "10.203.241.0/30");
        assert_eq!(allocate(&[], 1023).unwrap(), "10.203.255.252/30");
        assert!(allocate(&[], 1024).is_err());
    }

    #[test]
    fn skips_overlapping_wider_subnets_and_host_routes() {
        let occupied = [
            Ipv4Subnet::parse("10.203.240.0/24").unwrap(),
            Ipv4Subnet::parse("10.203.241.5/32").unwrap(),
        ];
        assert_eq!(allocate(&occupied, 0).unwrap(), "10.203.241.0/30");
        assert_eq!(allocate(&occupied, 1).unwrap(), "10.203.241.8/30");
    }

    #[test]
    fn fully_overlapping_routes_fail_instead_of_reusing_a_subnet() {
        for cidr in [DEFAULT_POOL, "10.0.0.0/8"] {
            let error = allocate(&[Ipv4Subnet::parse(cidr).unwrap()], 0).unwrap_err();
            assert!(error.to_string().contains("No free /30 subnet"));
        }
    }

    #[test]
    fn parses_routes_from_all_tables_without_reserving_the_default() {
        let routes = parse_routes(
            br#"[{"dst":"default"},{"dst":"0.0.0.0/0"},{"dst":"10.203.240.0/24","table":123},{"dst":"10.203.241.1","type":"local"},{}]"#,
        )
        .unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(allocate(&routes, 0).unwrap(), "10.203.241.4/30");
        assert!(parse_routes(b"not json").is_err());
    }

    #[test]
    fn parses_prefix_boundaries_and_rejects_invalid_addresses() {
        let all = Ipv4Subnet::parse("0.0.0.0/0").unwrap();
        let host = Ipv4Subnet::parse("10.203.240.5/32").unwrap();
        assert!(all.overlaps(host));
        assert_eq!(host, Ipv4Subnet::parse("10.203.240.5").unwrap());
        assert_eq!(
            Ipv4Subnet::parse("10.203.240.5/30").unwrap(),
            Ipv4Subnet::parse("10.203.240.4/30").unwrap()
        );
        assert!(Ipv4Subnet::parse("10.203.240.0/33").is_err());
        assert!(Ipv4Subnet::parse("10.203.999.0/30").is_err());
        assert!(Ipv4Subnet::parse("::1/128").is_err());
    }
}
