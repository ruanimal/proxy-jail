use anyhow::{Context, Result};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use users::os::unix::UserExt;

use crate::subnet::{self, Ipv4Subnet};

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

/// Get the runtime directory for PID files and tun2socks configs: $XDG_RUNTIME_DIR/proxy-jail
pub fn runtime_base_dir() -> PathBuf {
    dirs::runtime_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp").join(format!("proxy-jail-{}", users::get_current_uid())))
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
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create config directory: {parent:?}"))?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path.with_extension("lock"))
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
        if !path.exists() {
            return Ok(Config { jails: Vec::new() });
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;

        let mut config: Config = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {:?}", path))?;

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

        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }

        let content = serde_yaml::to_string(self)
            .context("Failed to serialize config")?;

        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {:?}", path))?;

        Ok(())
    }

    /// Find a jail by name
    pub fn find_jail(&self, name: &str) -> Option<&JailConfig> {
        self.jails.iter().find(|j| j.name == name)
    }

    /// Find a mutable jail by name
    #[allow(dead_code)]
    pub fn find_jail_mut(&mut self, name: &str) -> Option<&mut JailConfig> {
        self.jails.iter_mut().find(|j| j.name == name)
    }

    /// Add a new jail
    pub fn add_jail(&mut self, jail: JailConfig) -> Result<()> {
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
    let home = std::env::var("HOME")
        .context("HOME environment variable not set")?;
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
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        let path = directory.join("config.yaml");
        let lock = lock_config(&path).unwrap();
        let mut config = Config { jails: vec![subnet_jail("test", None)] };
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
        let loaded = loaded_rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
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
        assert_eq!(allocated(&subnet_jail("next", None), &jails), "10.203.240.8/30");
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
        assert_eq!(restored.jails[0].get_subnet(&restored.jails).unwrap(), "10.203.240.8/30");
        restored.jails.push(subnet_jail("next", None));
        assert!(restored.assign_missing_subnets_avoiding(&[]).unwrap());
        assert_eq!(restored.jails[2].subnet.as_deref(), Some("10.203.240.0/30"));
    }

    #[test]
    fn test_legacy_explicit_subnets_are_not_migrated_automatically() {
        let mut config = Config {
            jails: vec![subnet_jail("legacy", Some("10.10.0.0/24")), subnet_jail("new", None)],
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

        let mut config = Config { jails: vec![subnet_jail("blocked", None)] };
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
        };

        assert_eq!(jail.netns_name(), "pj-work");
    }
}
