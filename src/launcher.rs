use anyhow::{Context, Result};
use nix::unistd::{Gid, Uid, User};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use tracing::info;

use crate::config::JailConfig;
use crate::security;

pub struct AppHandle {
    pub child: Child,
    pub app_name: String,
    pub command: String,
}

/// The root intermediaries receive only a clean system environment and an
/// opaque JSON payload. setpriv drops privileges before our internal trampoline
/// restores the user's PATH, GUI environment or other application variables.
pub fn spawn_app(jail: &JailConfig, command: &str, args: &[String]) -> Result<AppHandle> {
    let user = security::invoking_user()?;
    let setpriv = security::trusted_program("setpriv")?;
    let executable = std::env::current_exe().context("Cannot locate proxy-jail")?;
    let environment = serde_json::to_string(&security::application_environment()?)?;
    info!(
        "Spawning application in namespace {}: {}",
        jail.netns_name(),
        command
    );
    let child = security::command("ip")?
        .args(["netns", "exec", &jail.netns_name()])
        .arg(setpriv)
        .arg(format!("--reuid={}", user.uid))
        .arg(format!("--regid={}", user.gid))
        .args(["--clear-groups", "--"])
        .arg(executable)
        .args(["__run-app", "--", command])
        .args(args)
        .env(security::APP_ENV, environment)
        .spawn()
        .context("Failed to spawn application through ip netns exec and setpriv")?;
    let app_name = std::path::Path::new(command)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| command.to_string());
    let command = std::iter::once(command)
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(AppHandle {
        child,
        app_name,
        command,
    })
}

/// Called after setpriv, without any further privilege elevation or config IO.
pub fn exec_app(command: &[String]) -> Result<()> {
    let user = User::from_uid(Uid::current())?.context("Cannot resolve application user")?;
    // Reject direct sudo invocation of this internal trampoline as a way to
    // bypass the normal privilege drop. A genuine root-shell launch is allowed.
    if Uid::effective().is_root() {
        anyhow::ensure!(
            security::invoking_user()?.uid.is_root(),
            "Application privileges have not been dropped"
        );
    }
    let environment = user_environment(&user)?;
    let error = Command::new(&command[0])
        .args(&command[1..])
        .env_clear()
        .envs(environment)
        .exec();
    Err(error).context("Failed to execute application")
}

pub fn user_environment(user: &User) -> Result<std::collections::BTreeMap<String, String>> {
    let mut environment = security::application_environment()?;
    environment.insert("HOME".into(), user.dir.to_string_lossy().into_owned());
    environment.insert("USER".into(), user.name.clone());
    environment.insert("LOGNAME".into(), user.name.clone());
    Ok(environment)
}

pub fn wait_app(handle: &mut AppHandle) -> Result<()> {
    let status = handle
        .child
        .wait()
        .context("Failed to wait for app child process")?;
    anyhow::ensure!(
        status.success(),
        "Command failed with exit code: {}",
        status.code().unwrap_or(-1)
    );
    Ok(())
}

/// Cache tools also drop credentials before exec and may then use user variables.
pub fn drop_to_user(uid: Uid, gid: Gid) -> std::io::Result<()> {
    if Uid::effective().is_root() {
        nix::unistd::setgroups(&[]).map_err(std::io::Error::from)?;
        nix::unistd::setgid(gid).map_err(std::io::Error::from)?;
        nix::unistd::setuid(uid).map_err(std::io::Error::from)?;
    }
    Ok(())
}
