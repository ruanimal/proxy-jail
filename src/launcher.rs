use anyhow::{Context, Result};
use std::env;
use std::process::Child;
use tracing::{debug, info};

use crate::config::JailConfig;

/// Handle returned by [`spawn_app`] so the caller can register the
/// launched process in the apps dir and then wait for it to exit.
pub struct AppHandle {
    /// The `Child` returned by `Command::spawn()`.  For `ip netns exec`
    /// the immediate child IS the target process (iproute2 does
    /// `setns` + `execve` rather than `fork` + `execve`), so its
    /// `id()` is the pid users will see in `ps` and `app list`.
    pub child: Child,
    /// The argv[0] basename of the user's command — what shows up in
    /// the `APP` column of `app list`.
    pub app_name: String,
    /// Full command line, for display in `app list`.
    pub command: String,
}

/// Spawn an application inside a network namespace.
///
/// Returns an [`AppHandle`] whose `child.id()` is the pid of the user's
/// process (because `ip netns exec` re-execs into the target, it does
/// not fork).  The caller is expected to:
/// 1. Call [`crate::jail::register_app`] with `child.id()`, `app_name`
///    and `command` so `app list` and `app stop` can find the process.
/// 2. Call `child.wait()` (or `child.wait_with_output()`) to reap it
///    and forward the exit status.
///
/// # Prerequisites
///
/// Caller must guarantee the netns `pj-{name}` exists and that
/// `tun2socks` is running inside it.  See [`crate::jail::run_app`].
pub fn spawn_app(jail: &JailConfig, command: &str, args: &[String]) -> Result<AppHandle> {
    let netns_name = jail.netns_name();

    info!(
        "Spawning application in namespace {}: {} {}",
        netns_name,
        command,
        args.join(" ")
    );

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

    // Spawn (do NOT wait — we want the child to outlive this function
    // call so the caller can register it).  We are root at this point
    // (the unprivileged parent re-exec'd via sudo), so `ip netns exec`
    // works directly without a nested `sudo`.
    let child = std::process::Command::new("ip")
        .args(&nsenter_args)
        .spawn()
        .context("Failed to spawn command in namespace")?;

    let app_name = std::path::Path::new(command)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| command.to_string());

    let cmdline = if args.is_empty() {
        command.to_string()
    } else {
        format!("{} {}", command, args.join(" "))
    };

    Ok(AppHandle {
        child,
        app_name,
        command: cmdline,
    })
}

/// Wait for an [`AppHandle`]'s child to exit and forward the status.
///
/// Returns `Ok(())` if the child exited successfully. Returns an error
/// (with the exit code) otherwise — same contract as the old
/// `launch_app` so the CLI surface is unchanged.
pub fn wait_app(handle: &mut AppHandle) -> Result<()> {
    let status = handle
        .child
        .wait()
        .context("Failed to wait for app child process")?;
    if !status.success() {
        anyhow::bail!(
            "Command failed with exit code: {}",
            status.code().unwrap_or(-1)
        );
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
