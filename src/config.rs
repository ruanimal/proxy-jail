use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use users::os::unix::UserExt;

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

    /// Subnet for the jail network (e.g., "10.10.0.0/24")
    /// If not specified, auto-assigned
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

impl Config {
    /// Load configuration from file
    pub fn load() -> Result<Self> {
        let path = config_path();
        if !path.exists() {
            return Ok(Config { jails: Vec::new() });
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;

        let config: Config = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {:?}", path))?;

        Ok(config)
    }

    /// Save configuration to file
    pub fn save(&self) -> Result<()> {
        let path = config_path();

        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }

        let content = serde_yaml::to_string(self)
            .context("Failed to serialize config")?;

        std::fs::write(&path, content)
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
        if self.jails.iter().any(|j| j.name == jail.name) {
            anyhow::bail!("Jail '{}' already exists", jail.name);
        }
        self.jails.push(jail);
        self.save()
    }

    /// Remove a jail by name
    pub fn remove_jail(&mut self, name: &str) -> Result<()> {
        let initial_len = self.jails.len();
        self.jails.retain(|j| j.name != name);
        if self.jails.len() == initial_len {
            anyhow::bail!("Jail '{}' not found", name);
        }
        self.save()
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

    /// Get the subnet, auto-assign if not specified
    pub fn get_subnet(&self, existing_jails: &[JailConfig]) -> String {
        if let Some(ref subnet) = self.subnet {
            return subnet.clone();
        }

        // Auto-assign subnet: 10.10.0.0/24, 10.10.1.0/24, etc.
        let used_subnets: Vec<u8> = existing_jails
            .iter()
            .filter_map(|j| {
                j.subnet.as_ref().and_then(|s| {
                    // Parse "10.10.X.0/24" format
                    let parts: Vec<&str> = s.split('.').collect();
                    if parts.len() >= 3 && parts[0] == "10" && parts[1] == "10" {
                        parts[2].parse::<u8>().ok()
                    } else {
                        None
                    }
                })
            })
            .collect();

        // Find first unused subnet
        for i in 0..=255 {
            if !used_subnets.contains(&i) {
                return format!("10.10.{}.0/24", i);
            }
        }

        // Fallback (should not happen in practice)
        "10.10.255.0/24".to_string()
    }
}

impl ProxyConfig {
    /// Get the SOCKS5 address string (host:port)
    pub fn socks5_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Get the SOCKS5 URL for tun2socks
    #[allow(dead_code)]
    pub fn socks5_url(&self) -> String {
        match &self.auth {
            Some(auth) => format!("socks5://{}:{}@{}:{}", auth.username, auth.password, self.host, self.port),
            None => format!("socks5://{}:{}", self.host, self.port),
        }
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
    fn test_subnet_auto_assignment() {
        let jail = JailConfig {
            name: "test".to_string(),
            proxy: ProxyConfig {
                host: "127.0.0.1".to_string(),
                port: 1080,
                proxy_type: "socks5".to_string(),
                auth: None,
            },
            subnet: None,
        };

        let existing = vec![];
        assert_eq!(jail.get_subnet(&existing), "10.10.0.0/24");

        let existing = vec![JailConfig {
            name: "other".to_string(),
            proxy: ProxyConfig {
                host: "127.0.0.1".to_string(),
                port: 1080,
                proxy_type: "socks5".to_string(),
                auth: None,
            },
            subnet: Some("10.10.0.0/24".to_string()),
        }];
        assert_eq!(jail.get_subnet(&existing), "10.10.1.0/24");
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
