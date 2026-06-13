use anyhow::{Context, Result};
use std::env;
use tracing::{debug, info};

use crate::config::JailConfig;

/// Launch an application inside a network namespace
pub fn launch_app(jail: &JailConfig, command: &str, args: &[String]) -> Result<()> {
    let netns_name = jail.netns_name();

    info!("Launching application in namespace {}: {} {}", netns_name, command, args.join(" "));

    // We're running as root (elevated via sudo), use ip netns exec to enter namespace
    // su drops privileges to the real user (SUDO_USER)
    let real_user = env::var("SUDO_USER").unwrap_or_else(|_| env::var("USER").unwrap_or_else(|_| "root".to_string()));
    let mut nsenter_args = vec![
        "netns".to_string(),
        "exec".to_string(),
        netns_name.clone(),
        "su".to_string(),
        "-".to_string(),
        real_user,
        "-c".to_string(),
    ];

    // Build the full command
    let full_command = if args.is_empty() {
        command.to_string()
    } else {
        format!("{} {}", command, args.join(" "))
    };
    nsenter_args.push(full_command);

    debug!("Running: ip {}", nsenter_args.join(" "));

    // Execute the command (we're root, so ip netns exec works directly)
    let status = std::process::Command::new("ip")
        .args(&nsenter_args)
        .status()
        .context("Failed to execute command in namespace")?;

    if !status.success() {
        anyhow::bail!("Command failed with exit code: {}", status.code().unwrap_or(-1));
    }

    Ok(())
}

/// Find the executable path for a command
#[allow(dead_code)]
pub fn find_executable(command: &str) -> Option<String> {
    let path = env::var("PATH").unwrap_or_default();
    let paths: Vec<&str> = path.split(':').collect();

    for dir in paths {
        let full_path = format!("{}/{}", dir, command);
        if std::path::Path::new(&full_path).exists() {
            return Some(full_path);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_executable() {
        // This test only works on Unix systems
        #[cfg(unix)]
        {
            // ls should be in PATH
            assert!(find_executable("ls").is_some());

            // nonexistent_command should not be found
            assert!(find_executable("nonexistent_command_12345").is_none());
        }
    }
}
