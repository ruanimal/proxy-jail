use anyhow::{Context, Result};
use nix::fcntl::{Flock, FlockArg};
use std::fs::{self, File};
use tracing::{debug, info, warn};

use crate::config::{Config, JailConfig};
use crate::network;
use crate::proxy;

/// Create a new jail
pub fn create_jail(name: &str, socks5_addr: &str, config: &mut Config) -> Result<()> {
    info!("Creating jail: {}", name);

    // Parse socks5 address
    let (host, port) = parse_socks5_addr(socks5_addr)?;

    // Create jail configuration
    let jail = JailConfig {
        name: name.to_string(),
        proxy: crate::config::ProxyConfig {
            host,
            port,
            proxy_type: "socks5".to_string(),
            auth: None,
        },
        subnet: None,
    };

    // Add to config and save
    config.add_jail(jail)?;

    info!("Jail '{}' created successfully", name);
    info!("To start the jail, run: proxy-jail app run {} -- <command>", name);

    Ok(())
}

/// List all jails and their status
pub fn list_jails(config: &Config) -> Result<()> {
    if config.jails.is_empty() {
        println!("No jails configured.");
        return Ok(());
    }

    println!("{:<15} {:<20} {:<15}", "NAME", "PROXY", "STATUS");
    println!("{:-<15} {:-<20} {:-<15}", "", "", "");

    for jail in &config.jails {
        let status = if network::netns_exists(&jail.netns_name()) {
            if proxy::check_tun2socks_running(jail)?.is_some() {
                "Running"
            } else {
                "Partial"
            }
        } else {
            "Stopped"
        };

        let proxy_addr = jail.proxy.socks5_addr();

        println!("{:<15} {:<20} {:<15}",
            jail.name,
            proxy_addr,
            status
        );
    }

    Ok(())
}

/// Stop a jail (kill tun2socks + delete netns)
pub fn stop_jail(name: &str, config: &Config) -> Result<()> {
    let jail = config.find_jail(name)
        .with_context(|| format!("Jail '{}' not found", name))?;

    info!("Stopping jail: {}", name);

    // Acquire lock
    let _lock = acquire_lock(jail)?;

    // Stop tun2socks
    proxy::stop_tun2socks(jail)?;

    // Get subnet for cleanup
    let subnet = jail.get_subnet(&config.jails);

    // Destroy network
    network::destroy_jail_network(jail, &subnet)?;

    // Clean up runtime directory
    let runtime_dir = jail.runtime_dir();
    if runtime_dir.exists() {
        fs::remove_dir_all(&runtime_dir)
            .with_context(|| format!("Failed to remove runtime directory: {:?}", runtime_dir))?;
    }

    info!("Jail '{}' stopped", name);
    Ok(())
}

/// Delete a jail (stop + remove config)
pub fn delete_jail(name: &str, config: &mut Config) -> Result<()> {
    info!("Deleting jail: {}", name);

    // Stop the jail first (ignore errors if already stopped)
    let _ = stop_jail(name, config);

    // Remove from config
    config.remove_jail(name)?;

    info!("Jail '{}' deleted", name);
    Ok(())
}

/// Run an application in a jail
pub fn run_app(
    jail_name: &str,
    command: &str,
    args: &[String],
    config: &Config,
) -> Result<()> {
    let jail = config.find_jail(jail_name)
        .with_context(|| format!("Jail '{}' not found", jail_name))?;

    info!("Running application in jail '{}': {} {}", jail_name, command, args.join(" "));

    // Acquire lock
    let _lock = acquire_lock(jail)?;

    // Lazy initialization: create network if it doesn't exist
    if !network::netns_exists(&jail.netns_name()) {
        info!("Jail not initialized, creating network...");
        initialize_jail(jail, config)?;
    }

    // Ensure tun2socks is running
    if proxy::check_tun2socks_running(jail)?.is_none() {
        info!("tun2socks not running, starting...");
        let subnet = jail.get_subnet(&config.jails);
        proxy::start_tun2socks(jail, &subnet)?;
    }

    // Launch the application
    crate::launcher::launch_app(jail, command, args)?;

    Ok(())
}

/// Stop an application in a jail
pub fn stop_app(jail_name: &str, app_name: &str, config: &Config) -> Result<()> {
    let jail = config.find_jail(jail_name)
        .with_context(|| format!("Jail '{}' not found", jail_name))?;

    info!("Stopping application '{}' in jail '{}'", app_name, jail_name);

    // Find processes matching the app name in the namespace
    let netns_name = jail.netns_name();

    // Use pgrep to find processes
    let output = std::process::Command::new("ip")
        .args(&["netns", "exec", &netns_name, "pgrep", "-f", app_name])
        .output()
        .context("Failed to search for processes")?;

    let pids = String::from_utf8_lossy(&output.stdout);

    if pids.trim().is_empty() {
        warn!("No processes found for '{}'", app_name);
        return Ok(());
    }

    // Kill each process
    for pid_str in pids.lines() {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            // Skip tun2socks process
            if let Some(tun2socks_pid) = proxy::check_tun2socks_running(jail)? {
                if pid == tun2socks_pid as i32 {
                    continue;
                }
            }

            debug!("Sending SIGTERM to PID: {}", pid);
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
        }
    }

    info!("Application '{}' stopped", app_name);
    Ok(())
}

/// Initialize a jail (create network + start tun2socks)
fn initialize_jail(jail: &JailConfig, config: &Config) -> Result<()> {
    let subnet = jail.get_subnet(&config.jails);

    // Create runtime directory
    let runtime_dir = jail.runtime_dir();
    fs::create_dir_all(&runtime_dir)
        .with_context(|| format!("Failed to create runtime directory: {:?}", runtime_dir))?;

    // Create network
    network::create_jail_network(jail, &subnet)?;

    // Start tun2socks
    proxy::start_tun2socks(jail, &subnet)?;

    Ok(())
}

/// Acquire a file lock for a jail
fn acquire_lock(jail: &JailConfig) -> Result<Flock<File>> {
    let lock_path = jail.lock_file();

    // Create parent directory if it doesn't exist
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create lock directory: {:?}", parent))?;
    }

    let file = File::create(&lock_path)
        .with_context(|| format!("Failed to create lock file: {:?}", lock_path))?;

    // Try to acquire an exclusive lock (non-blocking)
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => Ok(lock),
        Err((_, _)) => anyhow::bail!("Another instance is already running for jail '{}'", jail.name),
    }
}

/// Parse a SOCKS5 address string (host:port)
fn parse_socks5_addr(addr: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid SOCKS5 address format: {}. Expected host:port", addr);
    }

    let host = parts[0].to_string();
    let port: u16 = parts[1]
        .parse()
        .with_context(|| format!("Invalid port number: {}", parts[1]))?;

    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socks5_addr() {
        let (host, port) = parse_socks5_addr("127.0.0.1:1080").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 1080);

        let (host, port) = parse_socks5_addr("proxy.example.com:1080").unwrap();
        assert_eq!(host, "proxy.example.com");
        assert_eq!(port, 1080);

        assert!(parse_socks5_addr("invalid").is_err());
        assert!(parse_socks5_addr("host:99999").is_err());
    }
}
