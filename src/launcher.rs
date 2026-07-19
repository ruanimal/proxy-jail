use anyhow::{Context, Result};
use nix::unistd::{Uid, User};
use std::env;
use std::path::PathBuf;
use std::process::Child;
use tracing::{debug, info};
use users::os::unix::UserExt;

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
/// # Privileges and environment
///
/// This function runs in the **root** context (the unprivileged parent
/// re-exec'd via `sudo -E`, see `main.rs`).  We then `setpriv` back to
/// the real user so the GUI process owns its `~/.config`, DBus socket,
/// Xauthority, etc.  Because sudo invoked us with `-E`, the inherited
/// environment already contains DISPLAY / XAUTHORITY /
/// DBUS_SESSION_BUS_ADDRESS / XDG_RUNTIME_DIR / etc. — we do **not**
/// re-construct it from a temp file.
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

    // Locate setpriv.  util-linux has shipped it since 2.23 (2014);
    // every mainstream Linux distro has it.  Fail fast with a clear
    // error if absent.
    let setpriv = which_setpriv()?;

    // Resolve the real user.
    //
    // SUDO_USER is set by sudo to the invoking user.  If we are already
    // root (e.g. running the binary from a root shell for tests), fall
    // back to USER, then to the current uid as a last resort.
    let real_user_name = env::var("SUDO_USER")
        .ok()
        .or_else(|| env::var("USER").ok())
        .unwrap_or_default();
    let real_user = if real_user_name.is_empty() {
        User::from_uid(Uid::current())
            .ok()
            .flatten()
            .with_context(|| format!("Cannot resolve current uid {:?}", Uid::current()))?
    } else {
        User::from_name(&real_user_name)
            .with_context(|| format!("Cannot resolve user {:?}", real_user_name))?
            .with_context(|| format!("User {:?} does not exist", real_user_name))?
    };
    let real_uid = real_user.uid.as_raw();
    let real_gid = real_user.gid.as_raw();

    // Build the argv that runs as our final child.
    //
    // `ip netns exec <name> setpriv --reuid=UID --regid=GID --clear-groups -- <cmd> <args>...`
    //
    // `--clear-groups` drops supplementary groups so the user process
    // does not inherit any group memberships we (root) might have.  The
    // leading `ip netns exec` does the namespace jump; setpriv drops
    // privileges; the user's command runs as that user.
    let mut nsenter_args: Vec<String> = vec![
        "netns".into(),
        "exec".into(),
        netns_name.clone(),
        setpriv.to_string_lossy().into_owned(),
        format!("--reuid={}", real_uid),
        format!("--regid={}", real_gid),
        "--clear-groups".into(),
    ];
    nsenter_args.push(command.to_string());
    for a in args {
        nsenter_args.push(a.clone());
    }

    debug!("Running: ip {}", nsenter_args.join(" "));

    // Resolve the real user's home directory via the `users` crate
    // (nix::unistd::User doesn't expose it).  Fall back to $HOME if
    // resolution fails — better an approximate value than a spawn error.
    let real_home = users::get_user_by_uid(real_uid)
        .map(|u| u.home_dir().to_string_lossy().into_owned())
        .or_else(|| env::var("HOME").ok())
        .unwrap_or_else(|| format!("/home/{}", real_user.name));

    // Spawn `ip netns exec ...` and let the kernel take it from there.
    // Because `ip netns exec` re-execs into the user command (it does
    // not fork), `child.id()` is the real user pid and `child.wait()`
    // reaps it directly.
    let mut child_cmd = std::process::Command::new("ip");
    child_cmd.args(&nsenter_args);
    // Rewrite the environment before passing it to the user command.
    //
    // We must use `env_clear()` BEFORE `envs(...)`.  `Command::envs()`
    // on its own only overrides variables that were explicitly set on
    // the Command — it does NOT strip variables inherited from the
    // parent's environment.  So if we only called `envs(filtered)`,
    // SUDO_* (which sudo set on the root process) would still be
    // inherited by `ip` and propagated through to the user command.
    //
    // `env_clear()` breaks inheritance entirely; `envs(...)` then
    // installs only the variables we want the child to see.
    //
    // What we keep / change:
    // 1. Drop every SUDO_* variable (information leak about how the
    //    root process was invoked).
    // 2. Drop MAIL (sudo sets it to /var/mail/root, which is wrong for
    //    the unprivileged child).
    // 3. Restore USER, LOGNAME, HOME to the real user's values.
    // 4. Keep everything else (DISPLAY, XAUTHORITY, DBUS_*,
    //    XDG_RUNTIME_DIR, LANG, LC_*, PATH, ...).  PATH is preserved
    //    verbatim by `sudo -E --preserve-env=PATH` (see `main.rs`),
    //    so the caller's toolchain is intact.
    child_cmd.env_clear();
    let mut target_env: Vec<(String, String)> = Vec::with_capacity(64);
    for (k, v) in std::env::vars() {
        if k.starts_with("SUDO_") || k == "MAIL" {
            continue;
        }
        let v = match k.as_str() {
            "USER" | "LOGNAME" => real_user.name.clone(),
            "HOME" => real_home.clone(),
            _ => v,
        };
        target_env.push((k, v));
    }
    child_cmd.envs(target_env);

    let child = child_cmd
        .spawn()
        .with_context(|| {
            format!(
                "Failed to spawn `ip netns exec ... setpriv ... {}{}`",
                command,
                if args.is_empty() {
                    String::new()
                } else {
                    format!(" {}", args.join(" "))
                },
            )
        })?;

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

/// Locate the `setpriv` binary on $PATH.
///
/// We do this once at startup (in `spawn_app`) rather than relying on
/// a hard-coded `/usr/sbin/setpriv` so the binary works on minimal
/// installs (Alpine, containers) where the path differs.
fn which_setpriv() -> Result<PathBuf> {
    let path = env::var_os("PATH").unwrap_or_default();
    for dir in env::split_paths(&path) {
        let candidate = dir.join("setpriv");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    anyhow::bail!(
        "`setpriv` (from util-linux) is required but was not found on $PATH. \
         Install it via your package manager (`apt install util-linux`, \
         `apk add util-linux`, `dnf install util-linux`).",
    )
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
