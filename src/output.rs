use anyhow::Result;

use crate::config::JailConfig;
use crate::network;

fn proxy_endpoint(jail: &JailConfig, gateway: &str) -> String {
    if jail.proxy.host == "gateway" {
        format!("{}:{}", gateway, jail.proxy.port)
    } else {
        jail.proxy.socks5_addr()
    }
}

/// Human-facing operation details, without proxy usernames or passwords.
pub fn jail_summary(
    jail: &JailConfig,
    subnet: &str,
    outcome: &str,
    proxy_pid: Option<u32>,
) -> Result<String> {
    let gateway = network::get_gateway(subnet)?;
    let ns_ip = network::get_ns_ip(subnet)?;
    let auth = if jail.proxy.auth.is_some() {
        " (authentication enabled)"
    } else {
        ""
    };
    let mut message = format!(
        "Jail '{}' {}.\n  Namespace: {}\n  Proxy:     socks5://{}{}\n  Subnet:    {}\n  Gateway:   {}\n  Jail IP:   {}",
        jail.name,
        outcome,
        jail.netns_name(),
        proxy_endpoint(jail, &gateway),
        auth,
        subnet,
        gateway,
        ns_ip,
    );
    if let Some(pid) = proxy_pid {
        message.push_str(&format!(
            "\n  tun2socks: PID {}\n  Log:       {}",
            pid,
            jail.runtime_dir().join("tun2socks.log").display(),
        ));
    }
    Ok(message)
}

pub fn jail_table_header() -> String {
    format!(
        "{:<15} {:<22} {:<10} {:<20} {:<15} {:<15} {:<31} DNS SEARCH\n{:-<15} {:-<22} {:-<10} {:-<20} {:-<15} {:-<15} {:-<31} {:-<20}",
        "NAME",
        "PROXY",
        "STATUS",
        "SUBNET",
        "GATEWAY",
        "NETNS IP",
        "DNS",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    )
}

pub fn jail_table_row(jail: &JailConfig, subnet: &str, status: &str) -> Result<String> {
    let gateway = network::get_gateway(subnet)?;
    let ns_ip = if status == "Stopped" {
        "-".to_string()
    } else {
        network::get_ns_ip(subnet)?
    };
    let dns = jail
        .effective_dns_servers()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let dns_search = if jail.dns_search.is_empty() {
        "-".to_string()
    } else {
        jail.dns_search.join(",")
    };
    Ok(format!(
        "{:<15} {:<22} {:<10} {:<20} {:<15} {:<15} {:<31} {}",
        jail.name,
        proxy_endpoint(jail, &gateway),
        status,
        subnet,
        gateway,
        ns_ip,
        dns,
        dns_search,
    ))
}

pub fn app_registered(jail_name: &str, app_name: &str, app_id: &str, pid: i32) -> String {
    format!(
        "Application '{}' registered in jail '{}' (APP_ID={}, PID={}).",
        app_name, jail_name, app_id, pid,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyAuth, ProxyConfig};

    fn jail() -> JailConfig {
        JailConfig {
            name: "work".to_string(),
            proxy: ProxyConfig {
                host: "gateway".to_string(),
                port: 1080,
                proxy_type: "socks5".to_string(),
                auth: Some(ProxyAuth {
                    username: "private-user".to_string(),
                    password: "private-password".to_string(),
                }),
            },
            subnet: Some("10.203.240.4/30".to_string()),
            dns_servers: None,
            dns_search: Vec::new(),
        }
    }

    #[test]
    fn summary_includes_network_and_daemon_diagnostics_without_credentials() {
        let output = jail_summary(&jail(), "10.203.240.4/30", "started", Some(1234)).unwrap();
        for expected in [
            "Jail 'work' started.",
            "Namespace: pj-work",
            "socks5://10.203.240.5:1080 (authentication enabled)",
            "Subnet:    10.203.240.4/30",
            "Gateway:   10.203.240.5",
            "Jail IP:   10.203.240.6",
            "tun2socks: PID 1234",
            "tun2socks.log",
        ] {
            assert!(output.contains(expected), "missing {expected}: {output}");
        }
        assert!(!output.contains("private-user"));
        assert!(!output.contains("private-password"));
    }

    #[test]
    fn created_summary_does_not_claim_a_daemon_or_log_exists() {
        let output =
            jail_summary(&jail(), "10.203.240.4/30", "created (not started)", None).unwrap();
        assert!(output.contains("created (not started)"));
        assert!(!output.contains("tun2socks:"));
        assert!(!output.contains("Log:"));
    }

    #[test]
    fn table_shows_subnet_and_gateway_but_no_live_ip_for_stopped_jails() {
        let jail = jail();
        let header = jail_table_header();
        assert!(header.contains("SUBNET"));
        assert!(header.contains("GATEWAY"));
        assert!(header.contains("DNS"));
        assert!(header.contains("DNS SEARCH"));
        let stopped = jail_table_row(&jail, "10.203.240.4/30", "Stopped").unwrap();
        assert!(stopped.contains("10.203.240.4/30"));
        assert!(stopped.contains("10.203.240.5"));
        let columns: Vec<_> = stopped.split_whitespace().collect();
        assert_eq!(columns.len(), 8);
        assert_eq!(columns[5], "-");
        assert_eq!(columns[6], "1.1.1.1,8.8.8.8");
        assert_eq!(columns[7], "-");
        for state in ["Running", "Partial"] {
            let row = jail_table_row(&jail, "10.203.240.4/30", state).unwrap();
            let columns: Vec<_> = row.split_whitespace().collect();
            assert_eq!(columns.len(), 8);
            assert_eq!(columns[5], "10.203.240.6");
            assert_eq!(columns[6], "1.1.1.1,8.8.8.8");
            assert_eq!(columns[7], "-");
            assert!(!row.contains("private-user"));
            assert!(!row.contains("private-password"));
        }
    }

    #[test]
    fn table_shows_custom_dns_without_public_fallbacks() {
        let mut jail = jail();
        jail.name = "pp".to_string();
        jail.dns_servers = Some(vec!["10.251.1.1".parse().unwrap()]);
        let row = jail_table_row(&jail, "10.203.240.4/30", "Running").unwrap();
        let columns: Vec<_> = row.split_whitespace().collect();
        assert_eq!(columns.len(), 8);
        assert_eq!(columns[0], "pp");
        assert_eq!(columns[6], "10.251.1.1");
        assert_eq!(columns[7], "-");
        assert!(!row.contains("1.1.1.1"));
        assert!(!row.contains("8.8.8.8"));
    }

    #[test]
    fn table_preserves_multiple_dns_servers_and_search_suffixes_without_truncation() {
        let mut jail = jail();
        jail.dns_servers = Some(vec![
            "192.168.100.100".parse().unwrap(),
            "192.168.100.101".parse().unwrap(),
            "192.168.100.102".parse().unwrap(),
        ]);
        jail.dns_search = vec![
            "corp.example".to_string(),
            "long.internal.example".to_string(),
        ];
        for state in ["Running", "Partial", "Stopped"] {
            let row = jail_table_row(&jail, "10.203.240.4/30", state).unwrap();
            let columns: Vec<_> = row.split_whitespace().collect();
            assert_eq!(columns.len(), 8);
            assert_eq!(
                columns[6],
                "192.168.100.100,192.168.100.101,192.168.100.102"
            );
            assert_eq!(columns[7], "corp.example,long.internal.example");
            assert!(!row.contains("private-user"));
            assert!(!row.contains("private-password"));
        }
    }

    #[test]
    fn remote_proxy_address_is_not_rewritten_to_the_gateway() {
        let mut jail = jail();
        jail.proxy.host = "10.126.126.2".to_string();
        let output = jail_summary(&jail, "10.203.240.4/30", "already running", Some(1234)).unwrap();
        assert!(output.contains("already running"));
        assert!(output.contains("socks5://10.126.126.2:1080"));
        assert!(!output.contains("socks5://10.203.240.5:1080"));
    }

    #[test]
    fn application_message_identifies_the_registration_without_echoing_arguments() {
        assert_eq!(
            app_registered("work", "python", "0123456789abcdef", 1234),
            "Application 'python' registered in jail 'work' (APP_ID=0123456789abcdef, PID=1234)."
        );
    }
}
