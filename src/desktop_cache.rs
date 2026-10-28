use nix::unistd::{Gid, Uid};
use std::ffi::OsStr;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output};
use tracing::debug;

#[derive(Debug, Default)]
struct RefreshReport {
    refreshed: Vec<&'static str>,
    warnings: Vec<String>,
}

/// File changes have already succeeded, so cache failures are non-fatal.
pub fn refresh(dir: &Path, home: &Path, owner: (Uid, Gid)) {
    let kde = [
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_DESKTOP",
        "DESKTOP_SESSION",
    ]
    .iter()
    .filter_map(|name| std::env::var(name).ok())
    .any(|value| is_kde_session(&value));
    let version = std::env::var("KDE_SESSION_VERSION").ok();
    let report = refresh_with(dir, kde, version.as_deref(), |program, args| {
        cache_command(program, args, home, owner)?.output()
    });
    for warning in report.warnings {
        eprintln!("Warning: desktop entry changed, but {warning}");
    }
    if !report.refreshed.is_empty() {
        eprintln!(
            "Refreshed desktop application caches ({}).",
            report.refreshed.join(", ")
        );
    }
}

fn is_kde_session(value: &str) -> bool {
    value.split(':').any(|part| {
        let part = part.trim();
        part.eq_ignore_ascii_case("KDE") || part.to_ascii_lowercase().starts_with("plasma")
    })
}

fn refresh_with(
    dir: &Path,
    kde: bool,
    version: Option<&str>,
    mut run: impl FnMut(&str, &[&OsStr]) -> io::Result<Output>,
) -> RefreshReport {
    let mut report = RefreshReport::default();
    record_result(
        &mut report,
        "update-desktop-database",
        run("update-desktop-database", &[dir.as_os_str()]),
    );
    if kde {
        let candidates: &[&str] = match version {
            Some("5") => &["kbuildsycoca5"],
            Some("6") => &["kbuildsycoca6"],
            _ => &["kbuildsycoca6", "kbuildsycoca5"],
        };
        let mut found = false;
        for &program in candidates {
            match run(program, &[OsStr::new("--noincremental")]) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                result => {
                    record_result(&mut report, program, result);
                    found = true;
                    break;
                }
            }
        }
        if !found {
            report.warnings.push(format!(
                "the KDE application cache could not be refreshed: {} not found; \
                 install the cache tool matching your Plasma version",
                candidates.join(" / ")
            ));
        }
    }
    report
}

fn record_result(report: &mut RefreshReport, program: &'static str, result: io::Result<Output>) {
    match result {
        Ok(output) if output.status.success() => {
            debug!(program, stderr = %String::from_utf8_lossy(&output.stderr), "Desktop cache refreshed");
            report.refreshed.push(program);
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = stderr.trim();
            let suffix = if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            };
            report.warnings.push(format!(
                "{program} failed ({}){suffix}; refresh the cache manually",
                output.status
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            report.warnings.push(format!(
                "{program} was not found; install desktop-file-utils and run \
                 update-desktop-database on your user applications directory"
            ));
        }
        Err(error) => report
            .warnings
            .push(format!("could not run {program}: {error}")),
    }
}

fn cache_command(
    program: &str,
    args: &[&OsStr],
    home: &Path,
    owner: (Uid, Gid),
) -> io::Result<Command> {
    let user = users::get_user_by_uid(owner.0.as_raw())
        .ok_or_else(|| io::Error::other("Cannot resolve desktop cache owner"))?;
    if !Uid::effective().is_root() && (Uid::effective() != owner.0 || Gid::effective() != owner.1) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Cannot switch to the desktop entry owner",
        ));
    }
    let mut command = Command::new(program);
    command
        .args(args)
        .env("HOME", home)
        .env("USER", user.name())
        .env("LOGNAME", user.name())
        .env_remove("SUDO_UID")
        .env_remove("SUDO_GID")
        .env_remove("SUDO_USER");
    if Uid::effective().is_root() {
        // SAFETY: only credential-changing syscalls run between fork and exec.
        // Clear inherited root groups before dropping GID and UID. The GUI
        // session environment is inherited, but HOME/USER above belong to the
        // invoking user rather than sudo's root account.
        unsafe {
            command.pre_exec(move || {
                nix::unistd::setgroups(&[]).map_err(io::Error::from)?;
                nix::unistd::setgid(owner.1).map_err(io::Error::from)?;
                nix::unistd::setuid(owner.0).map_err(io::Error::from)?;
                Ok(())
            });
        }
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    fn success() -> io::Result<Output> {
        Ok(Output {
            status: ExitStatus::from_raw(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    fn missing() -> io::Result<Output> {
        Err(io::Error::new(io::ErrorKind::NotFound, "missing tool"))
    }

    #[test]
    fn non_kde_refreshes_only_the_changed_applications_directory() {
        let dir = Path::new("/tmp/applications with spaces");
        let mut calls = Vec::new();
        let report = refresh_with(dir, false, None, |program, args| {
            calls.push(program.to_string());
            assert_eq!(args, &[dir.as_os_str()]);
            success()
        });
        assert_eq!(calls, ["update-desktop-database"]);
        assert_eq!(report.refreshed, ["update-desktop-database"]);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn kde_uses_the_matching_session_version() {
        for (version, tool) in [("5", "kbuildsycoca5"), ("6", "kbuildsycoca6")] {
            let mut calls = Vec::new();
            let report = refresh_with(
                Path::new("/applications"),
                true,
                Some(version),
                |program, args| {
                    calls.push(program.to_string());
                    if program.starts_with("kbuildsycoca") {
                        assert_eq!(args, &[OsStr::new("--noincremental")]);
                    }
                    success()
                },
            );
            assert_eq!(calls, ["update-desktop-database", tool]);
            assert_eq!(report.refreshed, ["update-desktop-database", tool]);
            assert!(report.warnings.is_empty());
        }
    }

    #[test]
    fn unknown_kde_version_falls_back_to_5_only_when_6_is_missing() {
        let mut calls = Vec::new();
        let report = refresh_with(Path::new("/applications"), true, None, |program, _| {
            calls.push(program.to_string());
            if program == "kbuildsycoca6" {
                missing()
            } else {
                success()
            }
        });
        assert_eq!(
            calls,
            ["update-desktop-database", "kbuildsycoca6", "kbuildsycoca5"]
        );
        assert_eq!(
            report.refreshed,
            ["update-desktop-database", "kbuildsycoca5"]
        );
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn a_missing_mime_database_tool_does_not_skip_the_kde_cache() {
        let report = refresh_with(Path::new("/applications"), true, Some("6"), |program, _| {
            if program == "update-desktop-database" {
                missing()
            } else {
                success()
            }
        });
        assert_eq!(report.refreshed, ["kbuildsycoca6"]);
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("desktop-file-utils"));
    }

    #[test]
    fn tool_failures_include_stderr_without_trying_a_different_kde_major() {
        let mut calls = Vec::new();
        let report = refresh_with(Path::new("/applications"), true, None, |program, _| {
            calls.push(program.to_string());
            if program == "kbuildsycoca6" {
                Ok(Output {
                    status: ExitStatus::from_raw(256),
                    stdout: Vec::new(),
                    stderr: b"cache write denied\n".to_vec(),
                })
            } else {
                success()
            }
        });
        assert_eq!(calls, ["update-desktop-database", "kbuildsycoca6"]);
        assert_eq!(report.refreshed, ["update-desktop-database"]);
        assert!(report.warnings[0].contains("cache write denied"));
    }

    #[test]
    fn missing_tools_are_nonfatal_and_do_not_claim_success() {
        let report = refresh_with(Path::new("/applications"), true, Some("6"), |_, _| {
            missing()
        });
        assert!(report.refreshed.is_empty());
        assert_eq!(report.warnings.len(), 2);
        assert!(report.warnings[1].contains("kbuildsycoca6"));
    }

    #[test]
    fn spawn_errors_are_reported() {
        let report = refresh_with(Path::new("/applications"), false, None, |_, _| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "permission denied",
            ))
        });
        assert!(report.refreshed.is_empty());
        assert!(report.warnings[0].contains("permission denied"));
    }

    #[test]
    fn kde_session_detection_handles_multiple_desktops_and_plasma_names() {
        for session in [
            "KDE",
            "kde",
            "ubuntu:KDE",
            "plasma",
            "plasmawayland",
            "plasma6",
        ] {
            assert!(is_kde_session(session));
        }
        for session in ["", "GNOME", "XFCE", "not-kde"] {
            assert!(!is_kde_session(session));
        }
    }

    #[test]
    fn cache_subprocess_uses_the_owners_identity_and_home() {
        let owner = (Uid::effective(), Gid::effective());
        let home = Path::new("/tmp/desktop cache test home");
        let mut command = cache_command(
            "/bin/sh",
            &[
                OsStr::new("-c"),
                OsStr::new("printf '%s\\n' \"$HOME\" \"$USER\" \"$LOGNAME\"; id -u; id -g"),
            ],
            home,
            owner,
        )
        .unwrap();
        let output = command.output().unwrap();
        assert!(output.status.success());
        let user = users::get_user_by_uid(owner.0.as_raw()).unwrap();
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!(
                "{}\n{}\n{}\n{}\n{}\n",
                home.display(),
                user.name().to_string_lossy(),
                user.name().to_string_lossy(),
                owner.0,
                owner.1
            )
        );
    }
}
