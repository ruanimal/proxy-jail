use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::net::Ipv4Addr;
use tracing::Level;
use tracing_subscriber::EnvFilter;

mod config;
mod desktop;
mod desktop_cache;
mod dns;
mod dns_process;
mod jail;
mod launcher;
mod network;
mod output;
mod proxy;
mod security;
mod subnet;

/// Proxy Jail - Force GUI applications through SOCKS5 proxy using network namespaces
#[derive(Parser)]
#[command(name = "proxy-jail")]
#[command(version)]
#[command(about = "Force GUI applications through SOCKS5 proxy using network namespaces")]
struct Cli {
    /// Extra diagnostic logs (-v: info, -vv: debug, -vvv: trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage jails
    Jail {
        #[command(subcommand)]
        command: JailCommands,
    },
    /// Manage applications
    App {
        #[command(subcommand)]
        command: AppCommands,
    },
    /// Manage desktop entries
    Desktop {
        #[command(subcommand)]
        command: DesktopCommands,
    },
    /// Restore the application environment only after setpriv has dropped root.
    #[command(name = "__run-app", hide = true)]
    RunApp {
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Internal DNS relay, spawned inside a jail by proxy-jail.
    #[command(name = "__dns-relay", hide = true)]
    DnsRelay {
        #[arg(long = "upstream", required = true, value_parser = config::parse_dns_server)]
        upstream: Vec<Ipv4Addr>,
        #[arg(long)]
        parent: u32,
    },
}

#[derive(clap::Args)]
struct DnsArgs {
    /// DNS servers reachable from the jail's SOCKS5 exit (repeat or comma-separate)
    #[arg(long = "dns", visible_alias = "dns-server", value_name = "IP",
        value_delimiter = ',', value_parser = config::parse_dns_server)]
    servers: Option<Vec<Ipv4Addr>>,

    /// Search suffixes for short hostnames, not split DNS (repeat or comma-separate)
    #[arg(long = "dns-search", value_name = "DOMAIN", value_delimiter = ',',
        value_parser = config::parse_dns_search_domain)]
    search: Option<Vec<String>>,
}

#[derive(Subcommand)]
enum JailCommands {
    /// Create a new jail
    Create {
        /// Jail name (1-8 ASCII letters, digits, underscores or hyphens)
        #[arg(value_parser = config::parse_jail_name)]
        name: String,
        /// SOCKS5 proxy address (host:port or socks5://[username:password@]host:port)
        #[arg(long)]
        socks5: String,
        #[command(flatten)]
        dns: DnsArgs,
    },
    /// Show or update a jail's DNS; apply in place if its namespace is running
    Dns {
        /// Jail name
        #[arg(value_parser = config::parse_jail_name)]
        name: String,
        #[command(flatten)]
        dns: DnsArgs,
        /// Restore default DNS servers (1.1.1.1, 8.8.8.8)
        #[arg(long, conflicts_with = "servers")]
        reset_dns: bool,
        /// Remove all DNS search suffixes
        #[arg(long, conflicts_with = "search")]
        clear_dns_search: bool,
    },
    /// List all jails
    List,
    /// Start a jail (create network namespace + start tun2socks)
    Start {
        /// Jail name
        #[arg(value_parser = config::parse_jail_name)]
        name: String,
    },
    /// Stop a jail
    Stop {
        /// Jail name
        #[arg(value_parser = config::parse_jail_name)]
        name: String,
    },
    /// Delete a jail
    Delete {
        /// Jail name
        #[arg(value_parser = config::parse_jail_name)]
        name: String,
    },
}

#[derive(Subcommand)]
enum AppCommands {
    /// Execute a command in a jail
    Exec {
        /// Jail name
        #[arg(long, value_parser = config::parse_jail_name)]
        jail: String,
        /// Command to run (after `--`)
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// List running applications across jails
    List {
        /// Filter by jail name
        #[arg(long, value_parser = config::parse_jail_name)]
        jail: Option<String>,
    },
    /// Stop an application in a jail
    Stop {
        /// Jail name
        #[arg(long, value_parser = config::parse_jail_name)]
        jail: String,
        /// APP_ID from `app list`, or a unique prefix (not an application name)
        #[arg(value_name = "APP_ID")]
        app: String,
    },
}

#[derive(Subcommand)]
enum DesktopCommands {
    /// Create a desktop entry from a .desktop file
    Create {
        /// Jail name
        #[arg(long, value_parser = config::parse_jail_name)]
        jail: String,
        /// Path to .desktop file (or name found in system directories)
        #[arg(long)]
        from: String,
    },
    /// Delete a desktop entry
    Delete {
        /// Jail name
        #[arg(long, value_parser = config::parse_jail_name)]
        jail: String,
        /// .desktop file name (e.g. firefox.desktop or pj-xray-firefox.desktop)
        #[arg(value_parser = desktop::parse_desktop_name)]
        desktop_file: String,
    },
    /// List installed desktop entries
    List {
        /// Filter by jail name
        #[arg(long, value_parser = config::parse_jail_name)]
        jail: Option<String>,
    },
}

fn main() -> Result<()> {
    // Help, version and argument errors do not need root privileges.
    let cli = Cli::parse();

    if let Commands::RunApp { command } = &cli.command {
        return launcher::exec_app(command);
    }

    if !nix::unistd::Uid::effective().is_root() {
        let exe = std::env::current_exe().context("Failed to get current executable path")?;
        // The original GUI/toolchain environment is opaque JSON, not the
        // environment in which root or its system commands execute.
        let environment = serde_json::to_string(&security::capture_environment())?;
        anyhow::ensure!(
            environment.len() < 100_000,
            "Application environment is too large"
        );
        eprintln!("Elevating privileges via sudo...");
        let status = security::command("sudo")?
            .arg("-n")
            .arg("--")
            .arg(exe)
            .args(std::env::args_os().skip(1))
            .env(security::APP_ENV, environment)
            .status()
            .context("Failed to execute sudo; check the sudo-group proxy-jail rule")?;
        std::process::exit(status.code().unwrap_or(1));
    }

    // Initialize logging
    init_logging(cli.verbose);

    if let Commands::DnsRelay { upstream, parent } = &cli.command {
        let parent = *parent;
        return dns::serve(upstream.clone(), move || {
            // Bind privileged port 53 first, then drop every root privilege.
            if nix::unistd::Uid::effective().is_root() {
                nix::unistd::setgroups(&[]).map_err(std::io::Error::other)?;
                nix::unistd::setgid(nix::unistd::Gid::from_raw(65534))
                    .map_err(std::io::Error::other)?;
                nix::unistd::setuid(nix::unistd::Uid::from_raw(65534))
                    .map_err(std::io::Error::other)?;
            }
            // Until the manager records this process, it must not survive its
            // parent. The explicit parent check closes the prctl race.
            if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if unsafe { libc::getppid() } as u32 != parent {
                return Err(std::io::Error::other(
                    "DNS manager exited before relay registration",
                ));
            }
            use std::io::{Read, Write};
            let mut output = std::io::stdout().lock();
            writeln!(output, "READY")?;
            output.flush()?;
            let mut ack = [0];
            std::io::stdin().read_exact(&mut ack)?;
            if ack != *b"1" {
                return Err(std::io::Error::other("Invalid DNS manager acknowledgement"));
            }
            if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            writeln!(output, "ARMED")?;
            output.flush()
        });
    }
    security::private_directory(std::path::Path::new("/run/proxy-jail"))?;
    security::private_directory(&config::runtime_base_dir())?;

    // Load configuration
    let mut config = config::Config::load()?;

    match cli.command {
        Commands::Jail { command } => match command {
            JailCommands::Create { name, socks5, dns } => {
                jail::create_jail(
                    &name,
                    &socks5,
                    dns.servers,
                    dns.search.unwrap_or_default(),
                    &mut config,
                )?;
            }
            JailCommands::Dns {
                name,
                dns,
                reset_dns,
                clear_dns_search,
            } => {
                let search = if clear_dns_search {
                    Some(Vec::new())
                } else {
                    dns.search
                };
                jail::configure_jail_dns(&name, dns.servers, search, reset_dns, &mut config)?;
            }
            JailCommands::List => {
                jail::list_jails(&config)?;
            }
            JailCommands::Start { name } => {
                jail::start_jail(&name, &config)?;
            }
            JailCommands::Stop { name } => {
                if jail::stop_jail(&name, &config)? {
                    eprintln!(
                        "Jail '{}' stopped. Existing application processes were not terminated.",
                        name
                    );
                    eprintln!(
                        "Relaunch applications after starting the jail again to use its new network."
                    );
                } else {
                    eprintln!("Jail '{}' is already stopped.", name);
                }
            }
            JailCommands::Delete { name } => {
                jail::delete_jail(&name, &mut config)?;
            }
        },
        Commands::App { command } => match command {
            AppCommands::Exec { jail, command } => {
                if command.is_empty() {
                    anyhow::bail!("No command specified");
                }
                let cmd = &command[0];
                let args = &command[1..];
                jail::run_app(&jail, cmd, args, &config)?;
            }
            AppCommands::List { jail } => {
                jail::list_apps(jail.as_deref(), &config)?;
            }
            AppCommands::Stop { jail, app } => {
                jail::stop_app(&jail, &app, &config)?;
            }
        },
        Commands::Desktop { command } => match command {
            DesktopCommands::Create { jail, from } => {
                let jail_config = config
                    .find_jail(&jail)
                    .ok_or_else(|| anyhow::anyhow!("Jail '{}' not found", jail))?;

                desktop::desktop_install_from_file(jail_config, &from)?;
            }
            DesktopCommands::Delete { jail, desktop_file } => {
                let jail_config = config
                    .find_jail(&jail)
                    .ok_or_else(|| anyhow::anyhow!("Jail '{}' not found", jail))?;

                desktop::desktop_uninstall_from_file(jail_config, &desktop_file)?;
            }
            DesktopCommands::List { jail } => {
                let files = desktop::list_desktop_files(jail.as_deref())?;

                if files.is_empty() {
                    match jail.as_deref() {
                        Some(name) => println!("No desktop entries found for jail '{}'.", name),
                        None => println!("No proxy-jail desktop entries found."),
                    }
                } else {
                    println!("Installed proxy-jail desktop entries:");
                    for file in files {
                        println!("  {}", file.display());
                    }
                }
            }
        },
        Commands::DnsRelay { .. } | Commands::RunApp { .. } => {
            unreachable!("Internal command handled before configuration")
        }
    }

    Ok(())
}

/// Initialize logging with tracing
fn init_logging(verbosity: u8) {
    let level = match verbosity {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let filter = EnvFilter::from_default_env().add_directive(level.into());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn create_parses_repeated_and_comma_separated_dns_options() {
        let cli = Cli::try_parse_from([
            "proxy-jail",
            "jail",
            "create",
            "work",
            "--socks5",
            "127.0.0.1:1080",
            "--dns",
            "10.251.1.1,10.251.1.2",
            "--dns-server",
            "10.251.1.3",
            "--dns-search",
            "corp.example,lab.example",
            "--dns-search",
            "dev.example",
        ])
        .unwrap();
        let Commands::Jail {
            command: JailCommands::Create { name, dns, .. },
        } = cli.command
        else {
            panic!("expected jail create");
        };
        assert_eq!(name, "work");
        assert_eq!(
            dns.servers.unwrap(),
            [
                Ipv4Addr::new(10, 251, 1, 1),
                Ipv4Addr::new(10, 251, 1, 2),
                Ipv4Addr::new(10, 251, 1, 3),
            ]
        );
        assert_eq!(
            dns.search.unwrap(),
            ["corp.example", "lab.example", "dev.example"]
        );
    }

    #[test]
    fn existing_create_syntax_keeps_default_dns() {
        let cli = Cli::try_parse_from([
            "proxy-jail",
            "jail",
            "create",
            "work",
            "--socks5",
            "127.0.0.1:1080",
        ])
        .unwrap();
        let Commands::Jail {
            command: JailCommands::Create { dns, .. },
        } = cli.command
        else {
            panic!("expected jail create");
        };
        assert!(dns.servers.is_none());
        assert!(dns.search.is_none());
    }

    #[test]
    fn dns_inspection_and_partial_updates_do_not_imply_other_changes() {
        for extra in [
            vec![],
            vec!["--dns", "10.251.1.1"],
            vec!["--dns-search", "corp.example"],
        ] {
            let mut args = vec!["proxy-jail", "jail", "dns", "pp"];
            args.extend(&extra);
            let cli = Cli::try_parse_from(args).unwrap();
            let Commands::Jail {
                command:
                    JailCommands::Dns {
                        name,
                        dns,
                        reset_dns,
                        clear_dns_search,
                    },
            } = cli.command
            else {
                panic!("expected jail dns");
            };
            assert_eq!(name, "pp");
            assert_eq!(dns.servers.is_some(), extra.first() == Some(&"--dns"));
            assert_eq!(dns.search.is_some(), extra.first() == Some(&"--dns-search"));
            assert!(!reset_dns);
            assert!(!clear_dns_search);
        }
    }

    #[test]
    fn dns_reset_and_search_clear_can_be_requested_together() {
        let cli = Cli::try_parse_from([
            "proxy-jail",
            "jail",
            "dns",
            "pp",
            "--reset-dns",
            "--clear-dns-search",
        ])
        .unwrap();
        let Commands::Jail {
            command:
                JailCommands::Dns {
                    reset_dns,
                    clear_dns_search,
                    ..
                },
        } = cli.command
        else {
            panic!("expected jail dns");
        };
        assert!(reset_dns);
        assert!(clear_dns_search);
    }
}
