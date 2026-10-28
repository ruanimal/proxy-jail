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
