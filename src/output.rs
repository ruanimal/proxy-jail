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
        "{:<15} {:<22} {:<10} {:<20} {:<15} NETNS IP\n{:-<15} {:-<22} {:-<10} {:-<20} {:-<15} {:-<15}",
        "NAME", "PROXY", "STATUS", "SUBNET", "GATEWAY", "", "", "", "", "", "",
    )
}

pub fn jail_table_row(jail: &JailConfig, subnet: &str, status: &str) -> Result<String> {
    let gateway = network::get_gateway(subnet)?;
    let ns_ip = if status == "Stopped" {
        "-".to_string()
    } else {
        network::get_ns_ip(subnet)?
    };
    Ok(format!(
        "{:<15} {:<22} {:<10} {:<20} {:<15} {}",
        jail.name,
        proxy_endpoint(jail, &gateway),
        status,
        subnet,
        gateway,
        ns_ip,
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
        let stopped = jail_table_row(&jail, "10.203.240.4/30", "Stopped").unwrap();
        assert!(stopped.contains("10.203.240.4/30"));
        assert!(stopped.contains("10.203.240.5"));
        assert!(stopped.ends_with(" -"));
        for state in ["Running", "Partial"] {
            let row = jail_table_row(&jail, "10.203.240.4/30", state).unwrap();
            assert!(row.ends_with("10.203.240.6"));
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
