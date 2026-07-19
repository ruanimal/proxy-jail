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

    // Inside a network namespace, 127.0.0.1 refers to the namespace's own
    // loopback — not the host's.  Rewrite to "gateway" so the YAML config
    // is unambiguous, and the actual IP is resolved at runtime.
    let effective_host = if host == "localhost" || host == "127.0.0.1" || host == "::1" {
        warn!(
            "Proxy host '{}' refers to the local machine, but inside the network \
             namespace this would point to the namespace's own loopback. \
             Saving proxy host as 'gateway' — the actual IP will be resolved \
             at runtime. If your proxy listens on a specific LAN address, \
             prefer using that address directly.",
            host
        );
        "gateway".to_string()
    } else {
        host
    };

    // Create jail configuration
    let jail = JailConfig {
        name: name.to_string(),
        proxy: crate::config::ProxyConfig {
            host: effective_host,
            port,
            proxy_type: "socks5".to_string(),
            auth: None,
        },
        subnet: None,
    };

    // Add to config and save
    config.add_jail(jail)?;

    info!("Jail '{}' created successfully", name);
    info!("To start the jail, run: proxy-jail app exec --jail {} -- <command>", name);

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

/// Start a jail (create network namespace + start tun2socks)
pub fn start_jail(name: &str, config: &Config) -> Result<()> {
    let jail = config.find_jail(name)
        .with_context(|| format!("Jail '{}' not found", name))?;

    info!("Starting jail: {}", name);

    // Acquire lock
    let _lock = acquire_lock(jail)?;

    if network::netns_exists(&jail.netns_name())
        && proxy::check_tun2socks_running(jail)?.is_some()
    {
        info!("Jail '{}' is already running", name);
        return Ok(());
    }

    if network::netns_exists(&jail.netns_name()) {
        // Netns exists but tun2socks is not running — just restart tun2socks
        let subnet = jail.get_subnet(&config.jails);
        proxy::start_tun2socks(jail, &subnet)?;
    } else {
        // Full initialization: create network + start tun2socks
        initialize_jail(jail, config)?;
    }

    info!("Jail '{}' started", name);
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

    // Acquire lock only for the initialization phase. The lock must be
    // released before `launch_app` because that call blocks until the
    // user's command exits (e.g. a long-running server). Holding the lock
    // would prevent other commands from running in the same jail.
    {
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
    } // lock released here

    // Launch the application (blocks until the command finishes)
    crate::launcher::launch_app(jail, command, args)?;

    Ok(())
}

/// One process running inside a jail's network namespace.
///
/// `app_name` is `argv[0]` (the process's basename) and is what users
/// pass to `app stop` to terminate the process. `command` is the full
/// cmdline for diagnostic display only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppProcess {
    pub pid: i32,
    pub app_name: String,
    pub command: String,
}

/// Return the inode number of a network namespace identified by `netns`.
///
/// Runs `ip netns exec <netns> readlink /proc/self/ns/net` and parses the
/// trailing number from `net:[<inode>]`. Returns `Ok(None)` if the command
/// fails (netns absent, permission denied, etc.) so callers can degrade
/// gracefully instead of erroring out a partial listing.
fn netns_inode(netns: &str) -> Result<Option<u64>> {
    let output = std::process::Command::new("ip")
        .args(["netns", "exec", netns, "readlink", "/proc/self/ns/net"])
        .output();

    let out = match output {
        Ok(o) if o.status.success() => o,
        _ => return Ok(None),
    };

    let s = String::from_utf8_lossy(&out.stdout);
    // Expected: "net:[4026533311]\n"
    let inode: u64 = s
        .trim()
        .trim_start_matches("net:[")
        .trim_end_matches(']')
        .parse()
        .with_context(|| format!("Cannot parse netns inode from {:?}", s))?;
    Ok(Some(inode))
}

/// Walk `/proc/*/ns/net` and return every process whose network namespace
/// is the one identified by `inode`.
///
/// `read_cmdline(pid)` is injected so unit tests can supply canned
/// `/proc/<pid>/cmdline` content. It must return `(app_name, command)`
/// where `app_name` is argv[0] (the basename users pass to `app stop`)
/// and `command` is the full cmdline for display.
fn list_ns_processes_by_inode<F>(inode: u64, read_cmdline: F) -> Vec<AppProcess>
where
    F: Fn(i32) -> Option<(String, String)>,
{
    let target = format!("net:[{}]", inode);
    let mut out = Vec::new();

    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return out,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let pid: i32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // /proc/<pid>/ns/net is a symlink; readlink returns "net:[<inode>]"
        let link = match std::fs::read_link(format!("/proc/{}/ns/net", pid)) {
            Ok(l) => l,
            Err(_) => continue,
        };
        if link.to_string_lossy() != target {
            continue;
        }

        let (app_name, command) = match read_cmdline(pid) {
            Some(c) => c,
            None => continue,
        };
        out.push(AppProcess { pid, app_name, command });
    }

    out
}

/// Enumerate running user applications across all (or one) jail(s).
pub fn list_apps(jail_filter: Option<&str>, config: &Config) -> Result<()> {
    // Apply filter at config level, then sort so output is stable and
    // independent of config-file order.
    let mut jails: Vec<&JailConfig> = config
        .jails
        .iter()
        .filter(|j| jail_filter.map_or(true, |name| j.name == name))
        .collect();
    jails.sort_by(|a, b| a.name.cmp(&b.name));

    if let Some(name) = jail_filter {
        if jails.is_empty() {
            anyhow::bail!("Jail '{}' not found", name);
        }
    }

    // Column widths tuned to typical Linux process names. Wider names are
    // truncated by the {:<N} formatter; users can read the full arg list
    // from the COMMAND column.
    const JAIL_W: usize = 15;
    const PID_W: usize = 8;
    const APP_W: usize = 20;
    const CMD_MIN: usize = 20;

    let mut rows: Vec<(String, i32, String, String)> = Vec::new();

    for jail in &jails {
        // Skip jails whose netns has not been created yet (never started).
        if !network::netns_exists(&jail.netns_name()) {
            continue;
        }

        let inode = match netns_inode(&jail.netns_name())? {
            Some(i) => i,
            None => continue, // netns gone or unreadable — skip
        };

        let tun2socks_pid = proxy::check_tun2socks_running(jail)?;

        for proc in list_ns_processes_by_inode(inode, |pid| read_cmdline(pid)) {
            // Hide the internal tun2socks process from the user-facing list.
            if tun2socks_pid.map_or(false, |p| p as i32 == proc.pid) {
                continue;
            }
            rows.push((jail.name.clone(), proc.pid, proc.app_name, proc.command));
        }
    }

    if rows.is_empty() {
        println!("No running applications in proxy-jail.");
        return Ok(());
    }

    // Local bindings used in the format strings below (Rust's format!
    // does not support `::<N` width specifiers).
    let jail_w = JAIL_W;
    let pid_w = PID_W;
    let app_w = APP_W;
    let cmd_min = CMD_MIN;

    println!(
        "{:<jail_w$} {:<pid_w$} {:<app_w$} {}",
        "JAIL", "PID", "APP", "COMMAND",
    );
    println!(
        "{:->jail_w$} {:->pid_w$} {:->app_w$} {:->cmd_min$}",
        "", "", "", ""
    );
    for (jail, pid, app, cmd) in &rows {
        println!(
            "{:<jail_w$} {:<pid_w$} {:<app_w$} {}",
            jail, pid, app, cmd
        );
    }

    println!(
        "\nTip: copy the APP column to `app stop --jail {} <APP>`",
        jail_filter.unwrap_or("JAIL")
    );

    Ok(())
}

/// Stop an application in a jail.
///
/// Matches `app_name` against `argv[0]` (basename) of every process in the
/// jail's network namespace. This deliberately uses the same enumeration
/// path as `list_apps` so that whatever `list_apps` reports as `APP` can
/// be passed straight back into `stop`.
///
/// We **do not** use `pgrep -f` because it matches its own command line
/// (and the `sudo`/`ip` wrapper chain), which can cause the `stop`
/// command to kill its own ancestors.
pub fn stop_app(jail_name: &str, app_name: &str, config: &Config) -> Result<()> {
    let jail = config.find_jail(jail_name)
        .with_context(|| format!("Jail '{}' not found", jail_name))?;

    info!("Stopping application '{}' in jail '{}'", app_name, jail_name);

    // Skip if the jail has not been initialized yet (no netns).
    if !network::netns_exists(&jail.netns_name()) {
        warn!("Jail '{}' is not running", jail_name);
        return Ok(());
    }

    let inode = match netns_inode(&jail.netns_name())? {
        Some(i) => i,
        None => {
            warn!("Cannot read netns inode for jail '{}'", jail_name);
            return Ok(());
        }
    };

    let tun2socks_pid = proxy::check_tun2socks_running(jail)?;

    // Collect matching pids first, then kill — never let a kill of one
    // pid affect the iteration over /proc.
    let mut targets: Vec<i32> = list_ns_processes_by_inode(inode, |pid| read_cmdline(pid))
        .into_iter()
        .filter(|p| p.app_name == app_name)
        .filter(|p| tun2socks_pid.map_or(true, |t| t as i32 != p.pid))
        .map(|p| p.pid)
        .collect();

    if targets.is_empty() {
        warn!("No processes found for '{}' in jail '{}'", app_name, jail_name);
        return Ok(());
    }

    targets.sort_unstable();
    for pid in &targets {
        debug!("Sending SIGTERM to PID: {}", pid);
        // SAFETY: pid came from a directory scan of /proc; it is valid
        // at the time of read but may have exited by the time we kill.
        // kill() on a nonexistent pid returns ESRCH, which is harmless.
        unsafe {
            libc::kill(*pid, libc::SIGTERM);
        }
    }

    info!("Application '{}' stopped ({} process(es))", app_name, targets.len());
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

/// Parse raw `/proc/<pid>/cmdline` bytes (NUL-separated argv) into the
/// `(app_name, command)` tuple used by `read_cmdline`.
///
/// `app_name` is the basename of `argv[0]` (what users pass to
/// `app stop`); `command` is the full cmdline joined with spaces.
fn parse_cmdline_bytes(bytes: &[u8]) -> Option<(String, String)> {
    if bytes.is_empty() || bytes[0] == 0 {
        return None;
    }
    let parts: Vec<String> = bytes
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    if parts.is_empty() {
        return None;
    }
    let command = parts.join(" ");
    let app_name = std::path::Path::new(&parts[0])
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| parts[0].clone());
    Some((app_name, command))
}

/// Read a process's argv from `/proc/<pid>/cmdline` (NUL-separated).
///
/// Returns `(app_name, command)`:
/// - `app_name` is `argv[0]` (basename) — what users pass to `app stop`.
/// - `command` is the full cmdline for diagnostic display.
///
/// Falls back to `/proc/<pid>/comm` if cmdline is empty (kernel threads).
/// Returns `None` if the process disappears between directory scan and read.
fn read_cmdline(pid: i32) -> Option<(String, String)> {
    let path = format!("/proc/{}/cmdline", pid);
    if let Ok(bytes) = std::fs::read(&path) {
        if let Some(parsed) = parse_cmdline_bytes(&bytes) {
            return Some(parsed);
        }
    }
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| {
            let app_name = s.trim().to_string();
            (app_name.clone(), app_name)
        })
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

    #[test]
    fn test_parse_cmdline_bytes_simple() {
        // /proc/<pid>/cmdline is NUL-separated argv (no trailing NUL is
        // optional, so we don't rely on it).
        let bytes = b"firefox\0--new-instance\0%u";
        let (app, cmd) = parse_cmdline_bytes(bytes).unwrap();
        assert_eq!(app, "firefox");
        assert_eq!(cmd, "firefox --new-instance %u");
    }

    #[test]
    fn test_parse_cmdline_bytes_strips_path() {
        // argv[0] is the full path to the executable; users see just the
        // basename in the APP column.
        let bytes = b"/usr/bin/firefox\0--new-window\0";
        let (app, _cmd) = parse_cmdline_bytes(bytes).unwrap();
        assert_eq!(app, "firefox");
    }

    #[test]
    fn test_parse_cmdline_bytes_empty_or_kernel_thread() {
        // Empty (kernel threads have empty cmdline) and all-NUL are None.
        assert!(parse_cmdline_bytes(b"").is_none());
        assert!(parse_cmdline_bytes(b"\0\0").is_none());
    }

    /// `stop_app` filters by exact `app_name` match (argv[0] basename).
    /// This test exercises the filter logic in isolation: a "firefox"
    /// match must NOT also kill a process whose command line merely
    /// contains "firefox" as a substring (e.g. "/usr/share/firefox-extra/firefox-helper").
    #[test]
    fn test_stop_filter_is_exact_app_name() {
        let procs = vec![
            AppProcess { pid: 100, app_name: "firefox".into(),     command: "firefox".into() },
            AppProcess { pid: 200, app_name: "firefox".into(),     command: "firefox --new-window".into() },
            AppProcess { pid: 300, app_name: "firefox-helper".into(), command: "/usr/share/firefox-helper".into() },
        ];
        let want = "firefox";
        let mut targets: Vec<i32> = procs.iter()
            .filter(|p| p.app_name == want)
            .map(|p| p.pid)
            .collect();
        targets.sort_unstable();
        assert_eq!(targets, vec![100, 200]); // helper excluded
    }
}
