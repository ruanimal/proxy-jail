use anyhow::{Context, Result};
use std::env;
use tracing::{debug, info};

use crate::config::JailConfig;

/// Launch an application inside a network namespace.
///
/// # Prerequisites
///
/// This function only performs `nsenter` + `su` + `exec` and does **not**
/// ensure the jail is ready. The caller is responsible for guaranteeing:
///
/// 1. The network namespace `pj-{name}` exists (see [`crate::network::create_jail_network`]).
/// 2. `tun2socks` is running inside the namespace
///    (see [`crate::proxy::check_tun2socks_running`] /
///    [`crate::proxy::start_tun2socks`]).
///
/// Both prerequisites are satisfied by [`crate::jail::run_app`], which is
/// the only intended entry point in production. Call this function directly
/// only from tests or trusted internal code paths.
pub fn launch_app(jail: &JailConfig, command: &str, args: &[String]) -> Result<()> {
    let netns_name = jail.netns_name();

    info!("Launching application in namespace {}: {} {}", netns_name, command, args.join(" "));

    // Determine the real user from SUDO_USER (set automatically by sudo).
    let real_user = env::var("SUDO_USER")
        .or_else(|_| env::var("USER"))
        .unwrap_or_else(|_| "root".to_string());

    // Path to the environment file saved before sudo re-exec.
    // SUDO_UID is set automatically by sudo — we use it to locate the
    // temp file written by the unprivileged parent process.
    let env_file = match env::var("SUDO_UID") {
        Ok(uid) => format!("/tmp/pj-env-{}", uid),
        Err(_) => format!("/tmp/pj-env-{}", nix::unistd::Uid::current().as_raw()),
    };

    // Build the command that runs inside the namespace.
    // `su -s /bin/bash` runs a bash shell as the target user.
    // The `-c` argument sources the saved environment, then execs the app.
    // Using `exec` replaces the shell so signals reach the app directly.
    let raw_command = if args.is_empty() {
        format!("exec {}", command)
    } else {
        // Join args, escaping each for shell safety
        let escaped_args: Vec<String> = args.iter().map(|a| shell_escape(a)).collect();
        format!("exec {} {}", command, escaped_args.join(" "))
    };

    // Source the environment file (if it exists) and run the command.
    // `su -s /bin/bash` instead of `su -` avoids a login shell that would
    // overwrite the sourced environment with /etc/profile defaults.
    let shell_cmd = format!(
        "test -f '{}' && . '{}' ; {}",
        env_file, env_file, raw_command
    );

    let nsenter_args = vec![
        "netns".to_string(),
        "exec".to_string(),
        netns_name.clone(),
        "su".to_string(),
        "-s".to_string(),
        "/bin/bash".to_string(),
        real_user,
        "-c".to_string(),
        shell_cmd,
    ];

    debug!("Running: ip {}", nsenter_args.join(" "));

    // Execute the command (we're root after sudo re-exec, ip netns exec works directly)
    let status = std::process::Command::new("ip")
        .args(&nsenter_args)
        .status()
        .context("Failed to execute command in namespace")?;

    if !status.success() {
        anyhow::bail!("Command failed with exit code: {}", status.code().unwrap_or(-1));
    }

    Ok(())
}

/// Escape a string for safe use in a shell command.
fn shell_escape(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    // If it only contains safe characters, return as-is
    if s.chars().all(|c| c.is_alphanumeric() || "-_./=@:,+~".contains(c)) {
        return s.to_string();
    }
    // Otherwise, wrap in single quotes with internal quotes escaped
    format!("'{}'", s.replace('\'', "'\\''"))
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
