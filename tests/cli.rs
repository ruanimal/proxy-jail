use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    // Help and validation must work even when sudo is unavailable.
    Command::new(env!("CARGO_BIN_EXE_proxy-jail"))
        .args(args)
        .env("PATH", "")
        .output()
        .unwrap()
}

#[test]
fn help_does_not_require_sudo() {
    for args in [
        vec!["--help"],
        vec!["jail", "--help"],
        vec!["app", "--help"],
        vec!["desktop", "--help"],
    ] {
        let output = cli(&args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
    }
}

#[test]
fn version_does_not_require_sudo() {
    let output = cli(&["--version"]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        concat!("proxy-jail ", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn argument_errors_are_reported_before_privilege_elevation() {
    for args in [vec!["--unknown-option"], vec!["jail", "create", "work"]] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("error:"));
        assert!(!error.contains("Elevating privileges"));
        assert!(!error.contains("Failed to execute sudo"));
    }
}

#[test]
fn app_stop_documents_the_stable_application_identifier() {
    let output = cli(&["app", "stop", "--help"]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("<APP_ID>"));
    assert!(help.contains("unique prefix"));
    assert!(help.contains("not an application name"));

    let missing = cli(&["app", "stop", "--jail", "work"]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("<APP_ID>"));
}

#[test]
fn verbosity_is_available_after_subcommands() {
    let output = cli(&["jail", "list", "-v", "--help"]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--verbose"));
    assert!(help.contains("Extra diagnostic logs"));
}

#[test]
fn dns_help_documents_configuration_and_live_updates_without_sudo() {
    for subcommand in ["create", "dns"] {
        let output = cli(&["jail", subcommand, "--help"]);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(help.contains("--dns <IP>"));
        assert!(help.contains("--dns-search <DOMAIN>"));
        if subcommand == "dns" {
            assert!(help.contains("--reset-dns"));
            assert!(help.contains("--clear-dns-search"));
            assert!(help.contains("apply in place"));
        }
    }
}

#[test]
fn invalid_or_conflicting_dns_arguments_fail_before_sudo() {
    for extra in [
        vec!["--dns", "not-an-ip"],
        vec!["--dns", "::1"],
        vec!["--dns", "127.0.0.53"],
        vec!["--dns", ""],
        vec!["--dns"],
        vec!["--dns-search", "bad domain"],
        vec!["--dns-search", "corp\nnameserver 127.0.0.1"],
        vec!["--dns", "10.251.1.1", "--reset-dns"],
        vec!["--dns-search", "corp.example", "--clear-dns-search"],
    ] {
        let mut args = vec!["jail", "dns", "pp"];
        args.extend(extra);
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("error:"));
        assert!(!error.contains("Elevating privileges"));
    }
}

#[test]
fn unsafe_names_and_desktop_paths_are_rejected_before_sudo() {
    for args in [
        vec!["jail", "start", "../bad"],
        vec!["jail", "create", "123456789", "--socks5", "127.0.0.1:1080"],
        vec!["app", "exec", "--jail", "a/b", "--", "true"],
        vec!["desktop", "delete", "--jail", "work", "/etc/passwd"],
        vec!["desktop", "delete", "--jail", "work", "../victim"],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("Elevating privileges"));
    }
}

#[test]
fn application_trampoline_restores_environment_without_elevation() {
    let payload = serde_json::json!({
        "PATH": "/custom/toolchain:/usr/bin:/bin",
        "DISPLAY": ":test-display",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/test-bus",
        "SUDO_UID": "0",
        "HOME": "/wrong-home",
        "MAIL": "/var/mail/root",
        "TEST_VALUE": "spaces and symbols = stay intact"
    })
    .to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_proxy-jail"))
        .args(["__run-app", "--", "/usr/bin/env"])
        .env_clear()
        .env("PROXY_JAIL_APP_ENV", payload)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let environment = String::from_utf8(output.stdout).unwrap();
    assert!(environment.contains("PATH=/custom/toolchain:/usr/bin:/bin\n"));
    assert!(environment.contains("DISPLAY=:test-display\n"));
    assert!(environment.contains("DBUS_SESSION_BUS_ADDRESS=unix:path=/test-bus\n"));
    assert!(environment.contains("TEST_VALUE=spaces and symbols = stay intact\n"));
    assert!(!environment.contains("SUDO_"));
    assert!(!environment.contains("PROXY_JAIL_APP_ENV="));
    assert!(!environment.contains("HOME=/wrong-home"));
    assert!(!environment.contains("MAIL="));
    assert!(output.stderr.is_empty());
}

#[test]
fn invalid_application_environment_fails_without_executing_command() {
    for payload in [
        "not-json",
        "{\"BAD=KEY\":\"value\"}",
        "{\"KEY\":\"bad\\u0000value\"}",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_proxy-jail"))
            .args(["__run-app", "--", "/bin/echo", "must-not-run"])
            .env_clear()
            .env("PROXY_JAIL_APP_ENV", payload)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn application_trampoline_preserves_stdin_and_user_path_lookup() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;
    let base = std::env::var_os("PI_SCRATCH_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let directory = base.join(format!("app-path-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let tool = directory.join("user-tool");
    std::fs::write(&tool, "#!/bin/sh\n/usr/bin/id -u\n/bin/cat\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    let payload = serde_json::json!({"PATH": directory.to_str().unwrap()}).to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_proxy-jail"))
        .args(["__run-app", "--", "user-tool"])
        .env_clear()
        .env("PROXY_JAIL_APP_ENV", payload)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"stdin survives\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{}\nstdin survives\n", nix::unistd::getuid())
    );
    assert!(output.stderr.is_empty());
    std::fs::remove_dir_all(directory).unwrap();
}
