use anyhow::{Context, Result};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use crate::config::{Config, JailConfig};
use crate::network;
use crate::proxy;

/// Create a new jail
pub fn create_jail(name: &str, socks5_addr: &str, config: &mut Config) -> Result<()> {
    info!("Creating jail: {}", name);

    // Parse socks5 address
    let mut proxy = parse_socks5_addr(socks5_addr)?;
    let host = &proxy.host;

    // Inside a network namespace, 127.0.0.1 refers to the namespace's own
    // loopback — not the host's.  Rewrite to "gateway" so the YAML config
    // is unambiguous, and the actual IP is resolved at runtime.
    let effective_host = if host == "localhost" || host == "127.0.0.1" {
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
        host.clone()
    };
    proxy.host = effective_host;

    // Create jail configuration
    let jail = JailConfig {
        name: name.to_string(),
        proxy,
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

    println!("{:<15} {:<20} {:<15} {:<16}", "NAME", "PROXY", "STATUS", "NETNS IP");
    println!("{:-<15} {:-<20} {:-<15} {:-<16}", "", "", "", "");

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

        // Show the veth IP inside the netns only when the netns is up
        // — otherwise there's nothing to connect to.
        let ns_ip = if network::netns_exists(&jail.netns_name()) {
            let subnet = jail.get_subnet(&config.jails);
            network::get_ns_ip(&subnet).unwrap_or_else(|_| "-".into())
        } else {
            "-".to_string()
        };

        println!("{:<15} {:<20} {:<15} {:<16}",
            jail.name,
            proxy_addr,
            status,
            ns_ip,
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
    let subnet = {
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

        jail.get_subnet(&config.jails)
    }; // lock released here

    // Print a hint about how to reach services running inside the
    // netns.  We don't forward any ports automatically — the user runs
    // `socat` (or `ssh -L`) themselves.  See README for details.
    if let Ok(ns_ip) = network::get_ns_ip(&subnet) {
        info!(
            "Netns '{}' is up. To reach services inside it from the host:\n  \
             socat TCP-LISTEN:<host_port>,bind=127.0.0.1,fork,reuseaddr TCP:{}:<ns_port>",
            jail.netns_name(),
            ns_ip,
        );
    }

    // Spawn the application, register it so `app list` / `app stop` can
    // find it by `app_id`, then wait for it to exit.  The `app_id` is
    // generated *before* spawn so we can fail cleanly if the apps dir
    // is unwritable; on spawn failure we drop the record immediately.
    let mut handle = crate::launcher::spawn_app(jail, command, args)?;
    let pid = handle.child.id() as i32;

    let record = match register_app(jail, pid, &handle.app_name, &handle.command) {
        Ok(r) => r,
        Err(e) => {
            // Best-effort cleanup: kill the just-spawned process so it
            // doesn't outlive us.  The child might already be running,
            // which is why we send SIGTERM (graceful) and not SIGKILL.
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGTERM,
            );
            return Err(e).with_context(|| {
                format!(
                    "Spawned app (pid {}) but failed to register it; process was signalled.",
                    pid
                )
            });
        }
    };

    info!(
        "App registered: id={} pid={} name={}",
        record.app_id, record.pid, record.app_name
    );

    // Block until the user-facing process exits, then forward status.
    let result = crate::launcher::wait_app(&mut handle);

    // Whether the app succeeded or not, the record is now stale (the
    // process is gone).  Remove it so the next `app list` is clean.
    let _ = delete_app_record(jail, &record.app_id);

    result
}

/// Persistent metadata for a single `app exec` invocation.
///
/// `app_id` is generated at launch time and is the **stable identifier**
/// used by `app list` and `app stop`.  It is short (16 hex chars) and
/// unique per invocation, so two `python` invocations in the same jail
/// can be addressed independently even though their `app_name` is
/// identical.
///
/// The record is written to
/// `{runtime_dir}/apps/{app_id}.json` so it survives across CLI
/// invocations and `proxy-jail` restarts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppRecord {
    /// Stable, unique id for this invocation (16 hex chars).
    pub app_id: String,
    /// PID of the launched process. The process is the direct child of
    /// `ip netns exec` and may have already exited — `is_process_alive`
    /// checks `/proc/<pid>` before trusting this value.
    pub pid: i32,
    /// `argv[0]` basename at launch time (e.g. "firefox", "python").
    /// Used for display and for the legacy `app stop <name>` matcher.
    pub app_name: String,
    /// Full cmdline at launch time, for diagnostic display.
    pub command: String,
    /// Unix timestamp (seconds) at launch time.
    pub started_at: u64,
}

impl AppRecord {
    /// Path to the JSON file backing this record.
    pub fn file_path(&self, jail: &JailConfig) -> PathBuf {
        jail.apps_dir().join(format!("{}.json", self.app_id))
    }
}

/// Generate a fresh, 16-hex-char app id using `/dev/urandom`.
///
/// We do not pull in a `rand` crate just for this — `getrandom` would be
/// the obvious upgrade path. 8 random bytes is plenty: collision odds
/// across one user's session are negligible.
fn generate_app_id() -> Result<String> {
    use std::fs::File;
    use std::io::Read;

    let mut bytes = [0u8; 8];
    let mut f = File::open("/dev/urandom")
        .context("Failed to open /dev/urandom to generate app id")?;
    f.read_exact(&mut bytes)
        .context("Failed to read from /dev/urandom")?;
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

/// Return the current Unix timestamp in seconds, or 0 if the clock is
/// somehow before the epoch (effectively unreachable on Linux).
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Persist a new `AppRecord` to the jail's apps directory and return it.
///
/// Creates the directory if missing. Writes are atomic in practice
/// (small file, written and then renamed only logically — we use a
/// single `write` because the file is new and named with a unique id).
pub fn register_app(
    jail: &JailConfig,
    pid: i32,
    app_name: &str,
    command: &str,
) -> Result<AppRecord> {
    let app_id = generate_app_id()?;
    let record = AppRecord {
        app_id: app_id.clone(),
        pid,
        app_name: app_name.to_string(),
        command: command.to_string(),
        started_at: unix_now_secs(),
    };

    let dir = jail.apps_dir();
    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create apps dir: {:?}", dir))?;

    let path = record.file_path(jail);
    let json = serde_json::to_string_pretty(&record)
        .context("Failed to serialize AppRecord")?;
    let mut f = File::create(&path)
        .with_context(|| format!("Failed to create app record file: {:?}", path))?;
    f.write_all(json.as_bytes())
        .with_context(|| format!("Failed to write app record file: {:?}", path))?;
    f.sync_all().ok();

    debug!("Registered app {} (pid={}) at {:?}", app_id, pid, path);
    Ok(record)
}

/// Check if a process is alive by inspecting `/proc/<pid>`.
///
/// `/proc/<pid>` exists for every live process (including zombies
/// until the parent reaps them) and disappears on full reap. This is
/// the same heuristic used by `proxy::is_process_running`.
fn is_process_alive(pid: i32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

/// Read every `*.json` from `jail.apps_dir()`.
///
/// Skips files that fail to parse (they may be from a future schema or
/// a partial write). Caller can clean them up via [`cleanup_dead_apps`].
pub fn load_apps(jail: &JailConfig) -> Result<Vec<AppRecord>> {
    let dir = jail.apps_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut records = Vec::new();
    for entry in fs::read_dir(&dir)
        .with_context(|| format!("Failed to read apps dir: {:?}", dir))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Cannot read app record {:?}: {}", path, e);
                continue;
            }
        };
        match serde_json::from_str::<AppRecord>(&content) {
            Ok(r) => records.push(r),
            Err(e) => warn!("Cannot parse app record {:?}: {}", path, e),
        }
    }
    Ok(records)
}

/// Remove app record files whose process is no longer alive.
///
/// Returns the ids of records that were removed. Safe to call on every
/// `app list` / `app stop` so the directory doesn't accumulate stale
/// entries when users `kill` processes directly.
pub fn cleanup_dead_apps(jail: &JailConfig) -> Result<Vec<String>> {
    let mut removed = Vec::new();
    for record in load_apps(jail)? {
        if !is_process_alive(record.pid) {
            let path = record.file_path(jail);
            if let Err(e) = fs::remove_file(&path) {
                warn!("Failed to remove stale app record {:?}: {}", path, e);
                continue;
            }
            removed.push(record.app_id);
        }
    }
    Ok(removed)
}

/// Delete the record for `app_id`, ignoring if it does not exist.
pub fn delete_app_record(jail: &JailConfig, app_id: &str) -> Result<()> {
    let path = jail.apps_dir().join(format!("{}.json", app_id));
    if path.exists() {
        fs::remove_file(&path)
            .with_context(|| format!("Failed to remove app record: {:?}", path))?;
    }
    Ok(())
}

/// Resolve a user-supplied `query` against the live app set.
///
/// Matching is by `app_id` only (exact or unique prefix). `app_name`
/// (argv[0] basename) is intentionally NOT accepted because it is
/// ambiguous when more than one instance of the same binary is
/// running in the same jail — which is exactly the case this scheme
/// exists to disambiguate.
pub fn resolve_app_target(
    jail: &JailConfig,
    query: &str,
    live: &[AppRecord],
) -> Result<Vec<AppRecord>> {
    // 1. exact app_id
    let exact_id: Vec<_> = live.iter().filter(|r| r.app_id == query).cloned().collect();
    if !exact_id.is_empty() {
        return Ok(exact_id);
    }

    // 2. unique prefix on app_id
    let prefix: Vec<_> = live
        .iter()
        .filter(|r| r.app_id.starts_with(query))
        .cloned()
        .collect();
    if prefix.len() == 1 {
        return Ok(prefix);
    }
    if prefix.len() > 1 {
        anyhow::bail!(
            "App id prefix '{}' is ambiguous (matches {} ids). Use a longer prefix or the full id.",
            query,
            prefix.len()
        );
    }

    // Nothing matched
    let known: Vec<String> = live
        .iter()
        .map(|r| format!("{} ({})", r.app_id, r.app_name))
        .collect();
    anyhow::bail!(
        "No app matching '{}' in jail '{}'. Live apps: [{}]",
        query,
        jail.name,
        known.join(", "),
    )
}

/// Enumerate running user applications across all (or one) jail(s).
pub fn list_apps(jail_filter: Option<&str>, config: &Config) -> Result<()> {
    // Apply filter at config level, then sort so output is stable and
    // independent of config-file order.
    let mut jails: Vec<&JailConfig> = config
        .jails
        .iter()
        .filter(|j| jail_filter.is_none_or(|name| j.name == name))
        .collect();
    jails.sort_by(|a, b| a.name.cmp(&b.name));

    if let Some(name) = jail_filter
        && jails.is_empty()
    {
        anyhow::bail!("Jail '{}' not found", name);
    }

    // Column widths tuned to typical Linux process names. Wider names are
    // truncated by the {:<N} formatter; users can read the full arg list
    // from the COMMAND column.
    const JAIL_W: usize = 15;
    const ID_W: usize = 10;
    const PID_W: usize = 8;
    const APP_W: usize = 20;
    const CMD_MIN: usize = 20;

    let mut rows: Vec<(String, String, i32, String, String)> = Vec::new();

    for jail in &jails {
        // Skip jails whose netns has not been created yet (never started).
        if !network::netns_exists(&jail.netns_name()) {
            continue;
        }

        // Reap stale records (process died, file remained) so the listing
        // is always authoritative.  We deliberately ignore the result —
        // a missing apps dir simply means "no apps", which is fine.
        let _ = cleanup_dead_apps(jail);

        let records = load_apps(jail)?;
        for r in records {
            rows.push((
                jail.name.clone(),
                r.app_id.clone(),
                r.pid,
                r.app_name.clone(),
                r.command.clone(),
            ));
        }
    }

    if rows.is_empty() {
        println!("No running applications in proxy-jail.");
        return Ok(());
    }

    // Local bindings used in the format strings below (Rust's format!
    // does not support `::<N` width specifiers).
    let jail_w = JAIL_W;
    let id_w = ID_W;
    let pid_w = PID_W;
    let app_w = APP_W;
    let cmd_min = CMD_MIN;

    println!(
        "{:<jail_w$} {:<id_w$} {:<pid_w$} {:<app_w$} COMMAND",
        "JAIL", "APP_ID", "PID", "APP"
    );
    println!(
        "{:->jail_w$} {:->id_w$} {:->pid_w$} {:->app_w$} {:->cmd_min$}",
        "", "", "", "", ""
    );
    for (jail, id, pid, app, cmd) in &rows {
        println!(
            "{:<jail_w$} {:<id_w$} {:<pid_w$} {:<app_w$} {}",
            jail, id, pid, app, cmd
        );
    }

    println!(
        "\nTip: copy the APP_ID column to `app stop --jail {} <APP_ID>`",
        jail_filter.unwrap_or("JAIL")
    );

    Ok(())
}

/// Stop an application in a jail.
///
/// `query` is resolved through [`resolve_app_target`]: an exact or
/// prefixed `app_id` is preferred, with `app_name` (argv[0] basename)
/// as a fallback.  When the name lookup is ambiguous the function
/// errors out and lists the matching `app_id`s — this is the fix for
/// the previous "two `python`s in the same jail kill each other"
/// behavior.
///
/// We **do not** use `pgrep -f` because it matches its own command line
/// (and the `sudo`/`ip` wrapper chain), which can cause the `stop`
/// command to kill its own ancestors.
pub fn stop_app(jail_name: &str, query: &str, config: &Config) -> Result<()> {
    let jail = config.find_jail(jail_name)
        .with_context(|| format!("Jail '{}' not found", jail_name))?;

    info!("Stopping application '{}' in jail '{}'", query, jail_name);

    // Skip if the jail has not been initialized yet (no netns).
    if !network::netns_exists(&jail.netns_name()) {
        warn!("Jail '{}' is not running", jail_name);
        return Ok(());
    }

    // Reap stale records first so the matching set reflects reality.
    let _ = cleanup_dead_apps(jail);
    let live = load_apps(jail)?;

    let targets = resolve_app_target(jail, query, &live)?;

    // Collect matching pids first, then kill — never let a kill of one
    // pid affect the iteration.
    let mut pids: Vec<i32> = targets.iter().map(|r| r.pid).collect();
    pids.sort_unstable();
    pids.dedup();

    if pids.is_empty() {
        warn!("No processes found for '{}' in jail '{}'", query, jail_name);
        return Ok(());
    }

    for pid in &pids {
        debug!("Sending SIGTERM to PID: {}", pid);
        // SAFETY: pid came from the apps dir; it is valid at the time
        // of read but may have exited by the time we kill.  kill() on a
        // nonexistent pid returns ESRCH, which is harmless.
        unsafe {
            libc::kill(*pid, libc::SIGTERM);
        }
    }

    // Remove the record(s) we acted on so subsequent `app list` doesn't
    // show "running" processes we just killed.  cleanup_dead_apps on
    // the next call would also do this, but removing eagerly gives
    // users immediate feedback in scripts.
    for r in &targets {
        let _ = delete_app_record(jail, &r.app_id);
    }

    info!(
        "Application '{}' stopped ({} process(es))",
        query,
        pids.len()
    );
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

/// Parse a SOCKS5 address or URI without exposing credentials in errors.
fn parse_socks5_addr(addr: &str) -> Result<crate::config::ProxyConfig> {
    let uri = if addr.contains("://") {
        addr.to_string()
    } else {
        format!("socks5://{addr}")
    };
    let parsed = url::Url::parse(&uri)
        .map_err(|_| anyhow::anyhow!("Invalid SOCKS5 proxy address"))?;
    if matches!(parsed.host(), Some(url::Host::Ipv6(_))) {
        anyhow::bail!("IPv6 SOCKS5 proxy addresses are not supported");
    }
    if parsed.scheme() != "socks5"
        || parsed.host_str().is_none()
        || parsed.port().is_none()
        || !matches!(parsed.path(), "" | "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!("Expected a SOCKS5 proxy address with host and port, without path, query, or fragment");
    }

    let auth = if parsed.username().is_empty() && parsed.password().is_none() {
        None
    } else {
        let password = parsed.password().ok_or_else(|| {
            anyhow::anyhow!("SOCKS5 authentication requires a username and password")
        })?;
        let decode = |value: &str| -> Result<String> {
            let bytes = value.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' {
                    if i + 2 >= bytes.len()
                        || !bytes[i + 1].is_ascii_hexdigit()
                        || !bytes[i + 2].is_ascii_hexdigit()
                    {
                        anyhow::bail!("Invalid percent encoding in SOCKS5 credentials");
                    }
                    i += 3;
                } else {
                    i += 1;
                }
            }
            Ok(percent_encoding::percent_decode_str(value)
                .decode_utf8()
                .map_err(|_| anyhow::anyhow!("SOCKS5 credentials must be valid UTF-8"))?
                .into_owned())
        };
        let username = decode(parsed.username())?;
        if username.is_empty() {
            anyhow::bail!("SOCKS5 authentication requires a username and password");
        }
        Some(crate::config::ProxyAuth {
            username,
            password: decode(password)?,
        })
    };
    Ok(crate::config::ProxyConfig {
        host: parsed.host_str().unwrap().to_string(),
        port: parsed.port().unwrap(),
        proxy_type: "socks5".to_string(),
        auth,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_parse_socks5_addr() {
        for addr in ["127.0.0.1:1080", "socks5://127.0.0.1:1080"] {
            let proxy = parse_socks5_addr(addr).unwrap();
            assert_eq!(proxy.host, "127.0.0.1");
            assert_eq!(proxy.port, 1080);
            assert!(proxy.auth.is_none());
        }
        let proxy =
            parse_socks5_addr("socks5://user%40name:p%3Ass%2540@proxy.example.com:1080")
                .unwrap();
        assert_eq!(proxy.host, "proxy.example.com");
        let config_yaml = serde_yaml::to_string(&proxy).unwrap();
        let proxy: crate::config::ProxyConfig = serde_yaml::from_str(&config_yaml).unwrap();
        let generated = proxy.socks5_url(&proxy.host).unwrap();
        let roundtrip = parse_socks5_addr(&generated).unwrap();
        let auth = roundtrip.auth.unwrap();
        assert_eq!(auth.username, "user@name");
        assert_eq!(auth.password, "p:ss%40");

        for addr in [
            "invalid",
            "host:99999",
            "http://host:1080",
            "socks5://host:1080/path",
            "socks5://host:1080?query",
            "socks5://host:1080#fragment",
            "socks5://user@host:1080",
            "socks5://user:bad%zz@host:1080",
            "socks5://user:%FF@host:1080",
            "socks5://[::1]:1080",
        ] {
            assert!(parse_socks5_addr(addr).is_err(), "accepted {addr}");
        }
    }

    fn fake_jail() -> JailConfig {
        JailConfig {
            name: "work".to_string(),
            proxy: crate::config::ProxyConfig {
                host: "127.0.0.1".to_string(),
                port: 1080,
                proxy_type: "socks5".to_string(),
                auth: None,
            },
            subnet: None,
        }
    }

    #[test]
    fn test_app_record_roundtrip() {
        let r = AppRecord {
            app_id: "deadbeefcafef00d".to_string(),
            pid: 4242,
            app_name: "firefox".to_string(),
            command: "firefox --new-window".to_string(),
            started_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: AppRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn test_resolve_app_target_exact_id() {
        let jail = fake_jail();
        let live = vec![
            AppRecord {
                app_id: "aaaa1111aaaa1111".into(),
                pid: 100,
                app_name: "python".into(),
                command: "python -m http.server".into(),
                started_at: 0,
            },
            AppRecord {
                app_id: "bbbb2222bbbb2222".into(),
                pid: 200,
                app_name: "firefox".into(),
                command: "firefox".into(),
                started_at: 0,
            },
        ];
        let m = resolve_app_target(&jail, "bbbb2222bbbb2222", &live).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].pid, 200);
    }

    #[test]
    fn test_resolve_app_target_unique_prefix() {
        let jail = fake_jail();
        let live = vec![
            AppRecord {
                app_id: "aaaa1111aaaa1111".into(),
                pid: 100,
                app_name: "python".into(),
                command: "python".into(),
                started_at: 0,
            },
            AppRecord {
                app_id: "bbbb2222bbbb2222".into(),
                pid: 200,
                app_name: "firefox".into(),
                command: "firefox".into(),
                started_at: 0,
            },
        ];
        let m = resolve_app_target(&jail, "bbbb", &live).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].pid, 200);
    }

    #[test]
    fn test_resolve_app_target_ambiguous_prefix_errors() {
        let jail = fake_jail();
        let live = vec![
            AppRecord {
                app_id: "aaaa1111aaaa1111".into(),
                pid: 100,
                app_name: "python".into(),
                command: "python".into(),
                started_at: 0,
            },
            AppRecord {
                app_id: "aaaa2222bbbb3333".into(),
                pid: 200,
                app_name: "firefox".into(),
                command: "firefox".into(),
                started_at: 0,
            },
        ];
        let err = resolve_app_target(&jail, "aaaa", &live).unwrap_err();
        assert!(err.to_string().contains("ambiguous"));
    }

    /// `app_name` (argv[0] basename) is NOT a valid `app stop` target.
    /// Two `python` invocations in the same jail can no longer be
    /// addressed as a group — users must pick one of the app_ids.
    #[test]
    fn test_resolve_app_target_name_not_accepted() {
        let jail = fake_jail();
        let live = vec![
            AppRecord {
                app_id: "aaaa1111aaaa1111".into(),
                pid: 100,
                app_name: "python".into(),
                command: "python -m http.server".into(),
                started_at: 0,
            },
            AppRecord {
                app_id: "bbbb2222bbbb2222".into(),
                pid: 200,
                app_name: "python".into(),
                command: "python script.py".into(),
                started_at: 0,
            },
        ];
        // Single "python" must NOT match — even when there is only one,
        // we don't accept the name at all, so users always copy the id.
        let err = resolve_app_target(&jail, "python", &live).unwrap_err();
        assert!(
            err.to_string().contains("No app matching 'python'"),
            "msg: {}",
            err
        );
        // And of course an exact id still works.
        let m = resolve_app_target(&jail, "aaaa1111aaaa1111", &live).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].pid, 100);
    }

    #[test]
    fn test_resolve_app_target_unknown_errors_with_known_list() {
        let jail = fake_jail();
        let live = vec![AppRecord {
            app_id: "aaaa1111aaaa1111".into(),
            pid: 100,
            app_name: "firefox".into(),
            command: "firefox".into(),
            started_at: 0,
        }];
        let err = resolve_app_target(&jail, "chrome", &live).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("No app matching 'chrome'"));
        assert!(msg.contains("aaaa1111aaaa1111 (firefox)"));
    }

    /// Sanity check on `generate_app_id`: 16 hex chars, unique across
    /// many calls.  A collision in 256 invocations would mean
    /// `getrandom` is broken.
    #[test]
    fn test_generate_app_id_unique() {
        let mut seen: HashSet<String> = HashSet::new();
        for _ in 0..64 {
            let id = generate_app_id().unwrap();
            assert_eq!(id.len(), 16);
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(seen.insert(id), "duplicate app id");
        }
    }
}
