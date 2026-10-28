use anyhow::{Context, Result, ensure};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use users::os::unix::UserExt;

use crate::security;
use crate::subnet::{self, Ipv4Subnet};

/// veth-h-/veth-n- take seven bytes of Linux's 15-byte interface limit.
pub fn parse_jail_name(name: &str) -> std::result::Result<String, String> {
    if name.is_empty()
        || name.len() > 8
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        || !name.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err("Jail name must be 1-8 ASCII letters, digits, '_' or '-', starting with a letter or digit".into());
    }
    Ok(name.to_string())
}

const DEFAULT_DNS_SERVERS: [Ipv4Addr; 2] = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];

/// Shared validation for command-line values and YAML configurations.
pub fn parse_dns_server(value: &str) -> std::result::Result<Ipv4Addr, String> {
    let server = value
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("Invalid IPv4 DNS server: {value}"))?;
    if server.is_unspecified()
        || server.is_loopback()
        || server.is_multicast()
        || server.is_broadcast()
    {
        return Err(format!(
            "DNS server {server} cannot be reached through the jail's TUN/SOCKS5"
        ));
    }
    Ok(server)
}

pub fn parse_dns_search_domain(domain: &str) -> std::result::Result<String, String> {
    let name = domain.strip_suffix('.').unwrap_or(domain);
    let valid = !name.is_empty()
        && domain.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        });
    if !valid {
        return Err(format!("Invalid DNS search domain: {domain:?}"));
    }
    Ok(domain.to_string())
}

/// Resolve the real user's home directory, even when running under sudo.
/// Under sudo, $HOME=/root but SUDO_UID points to the invoking user.
pub fn real_home() -> PathBuf {
    if let Ok(uid) = std::env::var("SUDO_UID")
        && let Ok(uid) = uid.parse::<u32>()
        && let Some(user) = users::get_user_by_uid(uid)
    {
        return user.home_dir().to_path_buf();
    }
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"))
}

/// Get the configuration file path: ~/.config/proxy-jail/config.yaml
pub fn config_path() -> PathBuf {
    real_home()
        .join(".config")
        .join("proxy-jail")
        .join("config.yaml")
}

/// Privileged state never lives in caller-controlled XDG_RUNTIME_DIR or /tmp.
pub fn runtime_base_dir() -> PathBuf {
    let uid = security::invoking_user()
        .map(|user| user.uid.as_raw())
        .unwrap_or_else(|_| users::get_current_uid());
    PathBuf::from("/run/proxy-jail").join(uid.to_string())
}

/// User data directory for logs and desktop files
#[allow(dead_code)]
pub const USER_DATA_DIR: &str = ".local/share/proxy-jail";

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// List of jails
    pub jails: Vec<JailConfig>,
}

/// Jail configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailConfig {
    /// Jail name (used for netns name: pj-{name})
    pub name: String,

    /// SOCKS5 proxy configuration
    pub proxy: ProxyConfig,

    /// Subnet for the jail network (e.g., "10.203.240.0/30")
    /// If not specified, a non-overlapping /30 is auto-assigned and saved.
    #[serde(default)]
    pub subnet: Option<String>,

    /// DNS servers reached through this jail's TUN/SOCKS5 proxy.
    /// None uses public defaults; private DNS must be reachable at the proxy exit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_servers: Option<Vec<Ipv4Addr>>,

    /// Optional search domains for short internal hostnames (not split DNS).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_search: Vec<String>,
}

/// SOCKS5 proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy host
    pub host: String,

    /// Proxy port
    pub port: u16,

    /// Proxy type (currently only "socks5" supported)
    #[serde(default = "default_proxy_type")]
    pub proxy_type: String,

    /// Optional authentication
    #[serde(default)]
    pub auth: Option<ProxyAuth>,
}

/// Proxy authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

fn default_proxy_type() -> String {
    "socks5".to_string()
}

/// Keep the lock file in place: deleting it could create independent locks.
fn lock_config(path: &Path) -> Result<Flock<File>> {
    if path == config_path() {
        let user = security::invoking_user()?;
        for directory in [
            real_home().join(".config"),
            path.parent().unwrap().to_path_buf(),
        ] {
            let file = security::directory(&directory, true, 0o700)?;
            security::set_owner(&file, user.uid, user.gid)?;
        }
    }
    let file = security::private_file(&path.with_extension("lock"), false)
        .context("Failed to open configuration lock")?;
    Flock::lock(file, FlockArg::LockExclusive)
        .map_err(|(_, error)| error)
        .context("Failed to lock configuration")
}

impl Config {
    /// Load configuration from file
    pub fn load() -> Result<Self> {
        Self::load_from(&config_path())
    }

    fn load_from(path: &Path) -> Result<Self> {
        // Lock before reading, not only before saving: a concurrent loader
        // must reuse assignments already persisted by the first process.
        let _lock = lock_config(path)?;
        Self::load_unlocked(path)
    }

    fn load_unlocked(path: &Path) -> Result<Self> {
        let content = match security::read_private(path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Config { jails: Vec::new() });
            }
            Err(error) => {
                return Err(error).with_context(|| format!("Failed to read config file: {path:?}"));
            }
        };
        let mut config: Config = serde_yaml::from_slice(&content)
            .with_context(|| format!("Failed to parse config file: {path:?}"))?;
        for jail in &config.jails {
            parse_jail_name(&jail.name).map_err(anyhow::Error::msg)?;
            jail.validate_dns()?;
        }

        // Migrate legacy configurations once so later removals do not change
        // the subnet of a jail whose network namespace is already running.
        if config.assign_missing_subnets()? {
            config.save_to(path)?;
        }

        Ok(config)
    }

    /// Resolve and pin automatic assignments before configuration changes.
    fn assign_missing_subnets(&mut self) -> Result<bool> {
        if self.jails.iter().all(|jail| jail.subnet.is_some()) {
            return Ok(false);
        }
        self.assign_missing_subnets_avoiding(&subnet::host_ipv4_subnets()?)
    }

    fn assign_missing_subnets_avoiding(&mut self, occupied: &[Ipv4Subnet]) -> Result<bool> {
        let mut changed = false;
        for index in 0..self.jails.len() {
            if self.jails[index].subnet.is_none() {
                let subnet = self.jails[index].get_subnet_avoiding(&self.jails, occupied)?;
                self.jails[index].subnet = Some(subnet);
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Save configuration to file
    fn save_to(&self, path: &Path) -> Result<()> {
        let content = serde_yaml::to_string(self).context("Failed to serialize config")?;
        let mut file = security::private_file(path, false)
            .with_context(|| format!("Failed to write config file: {path:?}"))?;
        file.set_len(0)?;
        file.write_all(content.as_bytes())?;
        if path == config_path() {
            let user = security::invoking_user()?;
            security::set_owner(&file, user.uid, user.gid)?;
            let directory = security::directory(path.parent().unwrap(), false, 0)?;
            security::set_owner(&directory, user.uid, user.gid)?;
        }

        Ok(())
    }

    /// Find a jail by name
    pub fn find_jail(&self, name: &str) -> Option<&JailConfig> {
        self.jails.iter().find(|j| j.name == name)
    }

    /// Find a mutable jail by name
    pub fn find_jail_mut(&mut self, name: &str) -> Option<&mut JailConfig> {
        self.jails.iter_mut().find(|j| j.name == name)
    }

    /// Add a new jail
    pub fn add_jail(&mut self, jail: JailConfig) -> Result<()> {
        parse_jail_name(&jail.name).map_err(anyhow::Error::msg)?;
        jail.validate_dns()?;
        let path = config_path();
        let _lock = lock_config(&path)?;
        *self = Self::load_unlocked(&path)?;
        if self.jails.iter().any(|j| j.name == jail.name) {
            anyhow::bail!("Jail '{}' already exists", jail.name);
        }
        self.jails.push(jail);
        self.assign_missing_subnets()?;
        self.save_to(&path)
    }

    /// Update only DNS fields using the latest configuration under its lock.
    pub fn update_jail_dns(
        &mut self,
        name: &str,
        servers: Option<Vec<Ipv4Addr>>,
        search: Option<Vec<String>>,
        reset_servers: bool,
    ) -> Result<()> {
        self.update_jail_dns_at(&config_path(), name, servers, search, reset_servers)
    }

    fn update_jail_dns_at(
        &mut self,
        path: &Path,
        name: &str,
        servers: Option<Vec<Ipv4Addr>>,
        search: Option<Vec<String>>,
        reset_servers: bool,
    ) -> Result<()> {
        ensure!(
            !reset_servers || servers.is_none(),
            "Cannot set and reset DNS servers together"
        );
        let _lock = lock_config(path)?;
        let mut latest = Self::load_unlocked(path)?;
        let jail = latest
            .find_jail_mut(name)
            .with_context(|| format!("Jail '{name}' not found"))?;
        if reset_servers {
            jail.dns_servers = None;
        } else if let Some(servers) = servers {
            jail.dns_servers = Some(servers);
        }
        if let Some(search) = search {
            jail.dns_search = search;
        }
        jail.validate_dns()?;
        latest.save_to(path)?;
        *self = latest;
        Ok(())
    }

    /// Remove a jail by name
    pub fn remove_jail(&mut self, name: &str) -> Result<()> {
        let path = config_path();
        let _lock = lock_config(&path)?;
        *self = Self::load_unlocked(&path)?;
        let initial_len = self.jails.len();
        self.jails.retain(|j| j.name != name);
        if self.jails.len() == initial_len {
            anyhow::bail!("Jail '{}' not found", name);
        }
        self.save_to(&path)
    }
}

impl JailConfig {
    pub fn effective_dns_servers(&self) -> &[Ipv4Addr] {
        self.dns_servers.as_deref().unwrap_or(&DEFAULT_DNS_SERVERS)
    }

    pub fn validate_dns(&self) -> Result<()> {
        ensure!(
            !self.effective_dns_servers().is_empty(),
            "Jail '{}': dns_servers must not be empty",
            self.name
        );
        for server in self.effective_dns_servers() {
            parse_dns_server(&server.to_string())
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("Jail '{}': invalid DNS server", self.name))?;
        }
        for domain in &self.dns_search {
            parse_dns_search_domain(domain)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("Jail '{}': invalid DNS search domain", self.name))?;
        }
        Ok(())
    }

    /// Get the network namespace name
    pub fn netns_name(&self) -> String {
        format!("pj-{}", self.name)
    }

    /// Get the runtime directory for this jail
    pub fn runtime_dir(&self) -> PathBuf {
        runtime_base_dir().join(&self.name)
    }

    /// Get the tun2socks PID file path
    pub fn pid_file(&self) -> PathBuf {
        self.runtime_dir().join("tun2socks.pid")
    }

    /// Get the directory where per-app metadata files are stored.
    ///
    /// Each `app exec` invocation writes `{app_id}.json` here so that
    /// `app list` and `app stop` can address the process by its stable
    /// `app_id` rather than the ambiguous `argv[0]` basename.
    pub fn apps_dir(&self) -> PathBuf {
        self.runtime_dir().join("apps")
    }

    /// Get the lock file path for concurrent access
    pub fn lock_file(&self) -> PathBuf {
        runtime_base_dir().join(format!("{}.lock", self.name))
    }

    /// Get the pinned subnet, or allocate a /30 avoiding host and jail routes.
    pub fn get_subnet(&self, existing_jails: &[JailConfig]) -> Result<String> {
        if let Some(ref subnet) = self.subnet {
            return Ok(subnet.clone());
        }
        self.get_subnet_avoiding(existing_jails, &subnet::host_ipv4_subnets()?)
    }

    fn get_subnet_avoiding(
        &self,
        existing_jails: &[JailConfig],
        host_subnets: &[Ipv4Subnet],
    ) -> Result<String> {
        if let Some(ref subnet) = self.subnet {
            return Ok(subnet.clone());
        }

        let mut occupied = host_subnets.to_vec();
        for jail in existing_jails {
            if let Some(cidr) = &jail.subnet {
                occupied.push(
                    Ipv4Subnet::parse(cidr)
                        .with_context(|| format!("Invalid subnet for jail '{}'", jail.name))?,
                );
            }
        }

        // Earlier implicit jails reserve consecutive free subnets as well.
        let preceding_implicit = existing_jails
            .iter()
            .take_while(|jail| jail.name != self.name)
            .filter(|jail| jail.subnet.is_none())
            .count();
        subnet::allocate(&occupied, preceding_implicit)
    }
}

impl ProxyConfig {
    /// Get the SOCKS5 address string (host:port)
    pub fn socks5_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Build a SOCKS5 URL for tun2socks, encoding credential delimiters.
    pub fn socks5_url(&self, host: &str) -> Result<String> {
        let mut url = url::Url::parse(&format!("socks5://{}:{}", host, self.port))
            .context("Invalid SOCKS5 proxy host")?;
        if let Some(auth) = &self.auth {
            url.set_username(&auth.username.replace('%', "%25"))
                .expect("SOCKS5 URL supports a username");
            url.set_password(Some(&auth.password.replace('%', "%25")))
                .expect("SOCKS5 URL supports a password");
        }
        Ok(url.into())
    }
}

/// Get the user's data directory
#[allow(dead_code)]
pub fn user_data_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(USER_DATA_DIR))
}

/// Get the log directory
#[allow(dead_code)]
pub fn log_dir() -> Result<PathBuf> {
    Ok(user_data_dir()?.join("logs"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_reads_tighten_permissions_and_reject_links() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        let (fixture, _) = DnsConfigFixture::new();
        std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        Config::load_from(&fixture.path).unwrap();
        assert_eq!(fixture.path.metadata().unwrap().mode() & 0o777, 0o600);
        let linked = fixture.directory.join("linked.yaml");
        symlink(&fixture.path, &linked).unwrap();
        assert!(Config::load_from(&linked).is_err());
        let hardlink = fixture.directory.join("hardlink.yaml");
        std::fs::hard_link(&fixture.path, &hardlink).unwrap();
        assert!(Config::load_from(&hardlink).is_err());
        let lock_link = fixture.directory.join("unsafe.lock");
        symlink(&fixture.path, &lock_link).unwrap();
        assert!(lock_config(&fixture.directory.join("unsafe.yaml")).is_err());
    }

    struct DnsConfigFixture {
        directory: PathBuf,
        path: PathBuf,
    }

    impl DnsConfigFixture {
        fn new() -> (Self, Config) {
            let base = std::env::var_os("PI_SCRATCH_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let directory = base.join(format!(
                "proxy-jail-dns-config-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let path = directory.join("config.yaml");
            let config = Config {
                jails: vec![
                    subnet_jail("xray", Some("10.203.240.0/30")),
                    subnet_jail("pp", Some("10.203.240.4/30")),
                ],
            };
            config.save_to(&path).unwrap();
            (Self { directory, path }, config)
        }
    }

    impl Drop for DnsConfigFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn runtime_state_does_not_use_user_directories() {
        let user = security::invoking_user().unwrap();
        assert_eq!(
            runtime_base_dir(),
            PathBuf::from("/run/proxy-jail").join(user.uid.to_string())
        );
    }

    #[test]
    fn jail_names_reject_traversal_and_invalid_interface_names() {
        for name in [
            "",
            ".",
            "..",
            "../work",
            "/tmp",
            "a/b",
            "a\\b",
            "bad name",
            "-option",
            "123456789",
            "work\n",
        ] {
            assert!(parse_jail_name(name).is_err(), "{name:?}");
        }
        for name in ["work", "a_1-2", "12345678"] {
            assert_eq!(parse_jail_name(name).unwrap(), name);
        }
        let (fixture, _) = DnsConfigFixture::new();
        std::fs::write(
            &fixture.path,
            "jails: [{name: '../bad', proxy: {host: gateway, port: 1080}}]",
        )
        .unwrap();
        assert!(Config::load_from(&fixture.path).is_err());
    }

    #[test]
    fn test_dns_update_preserves_latest_unrelated_settings() {
        let (fixture, mut config) = DnsConfigFixture::new();
        config.find_jail_mut("pp").unwrap().dns_search = vec!["corp.example".to_string()];
        config.save_to(&fixture.path).unwrap();
        let mut concurrent = config.clone();
        concurrent.find_jail_mut("xray").unwrap().proxy.port = 2080;
        concurrent.save_to(&fixture.path).unwrap();
        let ip = Ipv4Addr::new(10, 251, 1, 1);

        config
            .update_jail_dns_at(&fixture.path, "pp", Some(vec![ip]), None, false)
            .unwrap();
        let saved = Config::load_from(&fixture.path).unwrap();
        let pp = saved.find_jail("pp").unwrap();
        assert_eq!(pp.dns_servers, Some(vec![ip]));
        assert_eq!(pp.dns_search, ["corp.example"]);
        assert_eq!(pp.subnet.as_deref(), Some("10.203.240.4/30"));
        assert_eq!(pp.proxy.port, 1080);
        assert_eq!(saved.find_jail("xray").unwrap().proxy.port, 2080);
        assert!(saved.find_jail("xray").unwrap().dns_servers.is_none());
    }

    #[test]
    fn test_dns_search_update_preserves_servers_and_reset_preserves_search() {
        let (fixture, mut config) = DnsConfigFixture::new();
        let ip = Ipv4Addr::new(10, 251, 1, 1);
        config
            .update_jail_dns_at(&fixture.path, "pp", Some(vec![ip]), None, false)
            .unwrap();
        config
            .update_jail_dns_at(
                &fixture.path,
                "pp",
                None,
                Some(vec!["corp.example".to_string()]),
                false,
            )
            .unwrap();
        assert_eq!(config.find_jail("pp").unwrap().dns_servers, Some(vec![ip]));
        config
            .update_jail_dns_at(&fixture.path, "pp", None, None, true)
            .unwrap();
        let pp = config.find_jail("pp").unwrap();
        assert!(pp.dns_servers.is_none());
        assert_eq!(pp.dns_search, ["corp.example"]);
        assert_eq!(pp.effective_dns_servers(), DEFAULT_DNS_SERVERS);
        config
            .update_jail_dns_at(&fixture.path, "pp", None, Some(Vec::new()), false)
            .unwrap();
        assert!(config.find_jail("pp").unwrap().dns_search.is_empty());
    }

    #[test]
    fn test_invalid_dns_updates_do_not_change_disk_or_memory() {
        let (fixture, mut config) = DnsConfigFixture::new();
        let original_file = std::fs::read(&fixture.path).unwrap();
        let original_memory = serde_yaml::to_string(&config).unwrap();
        for (servers, search, reset) in [
            (Some(Vec::new()), None, false),
            (Some(vec![Ipv4Addr::LOCALHOST]), None, false),
            (None, Some(vec!["bad domain".to_string()]), false),
            (Some(vec![Ipv4Addr::new(10, 251, 1, 1)]), None, true),
        ] {
            assert!(
                config
                    .update_jail_dns_at(&fixture.path, "pp", servers, search, reset)
                    .is_err()
            );
            assert_eq!(std::fs::read(&fixture.path).unwrap(), original_file);
            assert_eq!(serde_yaml::to_string(&config).unwrap(), original_memory);
        }
        assert!(
            config
                .update_jail_dns_at(&fixture.path, "missing", None, Some(Vec::new()), false)
                .is_err()
        );
        assert_eq!(std::fs::read(&fixture.path).unwrap(), original_file);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config {
            jails: vec![JailConfig {
                name: "test".to_string(),
                proxy: ProxyConfig {
                    host: "127.0.0.1".to_string(),
                    port: 1080,
                    proxy_type: "socks5".to_string(),
                    auth: None,
                },
                subnet: None,
                dns_servers: None,
                dns_search: Vec::new(),
            }],
        };

        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(yaml.contains("test"));
        assert!(yaml.contains("127.0.0.1"));
        assert!(yaml.contains("1080"));
    }

    #[test]
    fn test_load_waits_for_config_lock_before_reading_assignments() {
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let base = std::env::var_os("PI_SCRATCH_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let directory = base.join(format!(
            "proxy-jail-config-lock-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = directory.join("config.yaml");
        let lock = lock_config(&path).unwrap();
        let mut config = Config {
            jails: vec![subnet_jail("test", None)],
        };
        config.save_to(&path).unwrap();

        let (started_tx, started_rx) = mpsc::channel();
        let (loaded_tx, loaded_rx) = mpsc::channel();
        let other_path = path.clone();
        let loader = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            loaded_tx.send(Config::load_from(&other_path)).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            loaded_rx.recv_timeout(Duration::from_millis(100)),
            Err(RecvTimeoutError::Timeout)
        ));

        config.jails[0].subnet = Some("10.203.240.0/30".to_string());
        config.save_to(&path).unwrap();
        drop(lock);
        let loaded = loaded_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        loader.join().unwrap();
        assert_eq!(loaded.jails[0].subnet.as_deref(), Some("10.203.240.0/30"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn subnet_jail(name: &str, subnet: Option<&str>) -> JailConfig {
        JailConfig {
            name: name.to_string(),
            proxy: ProxyConfig {
                host: "gateway".to_string(),
                port: 1080,
                proxy_type: "socks5".to_string(),
                auth: None,
            },
            subnet: subnet.map(str::to_string),
            dns_servers: None,
            dns_search: Vec::new(),
        }
    }

    fn allocated(jail: &JailConfig, existing: &[JailConfig]) -> String {
        jail.get_subnet_avoiding(existing, &[]).unwrap()
    }

    #[test]
    fn test_subnet_auto_assignment() {
        let jail = subnet_jail("test", None);
        assert_eq!(allocated(&jail, &[]), "10.203.240.0/30");
        let existing = vec![subnet_jail("other", Some("10.203.240.0/30"))];
        assert_eq!(allocated(&jail, &existing), "10.203.240.4/30");
    }

    #[test]
    fn test_subnet_auto_assignment_accounts_for_implicit_jails() {
        let jails = vec![subnet_jail("xray", None), subnet_jail("pp", None)];
        assert_eq!(allocated(&jails[0], &jails), "10.203.240.0/30");
        assert_eq!(allocated(&jails[1], &jails), "10.203.240.4/30");
        assert_eq!(
            allocated(&subnet_jail("next", None), &jails),
            "10.203.240.8/30"
        );
    }

    #[test]
    fn test_subnet_auto_assignment_reserves_explicit_subnets() {
        let jails = vec![
            subnet_jail("first", None),
            subnet_jail("second", None),
            subnet_jail("explicit", Some("10.203.240.4/30")),
        ];
        assert_eq!(allocated(&jails[0], &jails), "10.203.240.0/30");
        assert_eq!(allocated(&jails[1], &jails), "10.203.240.8/30");
        assert_eq!(allocated(&jails[2], &jails), "10.203.240.4/30");
    }

    #[test]
    fn test_automatic_subnets_are_pinned_and_preserved() {
        let mut config = Config {
            jails: vec![
                subnet_jail("first", None),
                subnet_jail("second", None),
                subnet_jail("explicit", Some("10.203.240.4/30")),
            ],
        };
        assert!(config.assign_missing_subnets_avoiding(&[]).unwrap());
        assert_eq!(config.jails[0].subnet.as_deref(), Some("10.203.240.0/30"));
        assert_eq!(config.jails[1].subnet.as_deref(), Some("10.203.240.8/30"));
        assert_eq!(config.jails[2].subnet.as_deref(), Some("10.203.240.4/30"));
        assert!(!config.assign_missing_subnets_avoiding(&[]).unwrap());

        let yaml = serde_yaml::to_string(&config).unwrap();
        let mut restored: Config = serde_yaml::from_str(&yaml).unwrap();
        restored.jails.remove(0);
        assert!(!restored.assign_missing_subnets_avoiding(&[]).unwrap());
        assert_eq!(
            restored.jails[0].get_subnet(&restored.jails).unwrap(),
            "10.203.240.8/30"
        );
        restored.jails.push(subnet_jail("next", None));
        assert!(restored.assign_missing_subnets_avoiding(&[]).unwrap());
        assert_eq!(restored.jails[2].subnet.as_deref(), Some("10.203.240.0/30"));
    }

    #[test]
    fn test_legacy_explicit_subnets_are_not_migrated_automatically() {
        let mut config = Config {
            jails: vec![
                subnet_jail("legacy", Some("10.10.0.0/24")),
                subnet_jail("new", None),
            ],
        };
        assert!(config.assign_missing_subnets_avoiding(&[]).unwrap());
        assert_eq!(config.jails[0].subnet.as_deref(), Some("10.10.0.0/24"));
        assert_eq!(config.jails[1].subnet.as_deref(), Some("10.203.240.0/30"));
    }

    #[test]
    fn test_auto_assignment_avoids_host_routes_and_reports_exhaustion() {
        let mut config = Config {
            jails: vec![subnet_jail("first", None), subnet_jail("second", None)],
        };
        let occupied = [Ipv4Subnet::parse("10.203.240.0/24").unwrap()];
        assert!(config.assign_missing_subnets_avoiding(&occupied).unwrap());
        assert_eq!(config.jails[0].subnet.as_deref(), Some("10.203.241.0/30"));
        assert_eq!(config.jails[1].subnet.as_deref(), Some("10.203.241.4/30"));

        let mut config = Config {
            jails: vec![subnet_jail("blocked", None)],
        };
        let occupied = [Ipv4Subnet::parse(subnet::DEFAULT_POOL).unwrap()];
        assert!(config.assign_missing_subnets_avoiding(&occupied).is_err());
        assert!(config.jails[0].subnet.is_none());
    }

    #[test]
    fn test_netns_name() {
        let jail = JailConfig {
            name: "work".to_string(),
            proxy: ProxyConfig {
                host: "127.0.0.1".to_string(),
                port: 1080,
                proxy_type: "socks5".to_string(),
                auth: None,
            },
            subnet: None,
            dns_servers: None,
            dns_search: Vec::new(),
        };

        assert_eq!(jail.netns_name(), "pj-work");
    }
}
