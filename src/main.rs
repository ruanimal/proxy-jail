use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::EnvFilter;

mod config;
mod desktop;
mod jail;
mod launcher;
mod network;
mod proxy;

/// Proxy Jail - Force GUI applications through SOCKS5 proxy using network namespaces
#[derive(Parser)]
#[command(name = "proxy-jail")]
#[command(version = "0.1.0")]
#[command(about = "Force GUI applications through SOCKS5 proxy using network namespaces")]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
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
}

#[derive(Subcommand)]
enum JailCommands {
    /// Create a new jail
    Create {
        /// Jail name
        name: String,
        /// SOCKS5 proxy address (host:port or socks5://[username:password@]host:port)
        #[arg(long)]
        socks5: String,
    },
    /// List all jails
    List,
    /// Start a jail (create network namespace + start tun2socks)
    Start {
        /// Jail name
        name: String,
    },
    /// Stop a jail
    Stop {
        /// Jail name
        name: String,
    },
    /// Delete a jail
    Delete {
        /// Jail name
        name: String,
    },
}

#[derive(Subcommand)]
enum AppCommands {
    /// Execute a command in a jail
    Exec {
        /// Jail name
        #[arg(long)]
        jail: String,
        /// Command to run (after `--`)
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// List running applications across jails
    List {
        /// Filter by jail name
        #[arg(long)]
        jail: Option<String>,
    },
    /// Stop an application in a jail
    Stop {
        /// Jail name
        #[arg(long)]
        jail: String,
        /// Application name
        app: String,
    },
}

#[derive(Subcommand)]
enum DesktopCommands {
    /// Create a desktop entry from a .desktop file
    Create {
        /// Jail name
        #[arg(long)]
        jail: String,
        /// Path to .desktop file (or name found in system directories)
        #[arg(long)]
        from: String,
    },
    /// Delete a desktop entry
    Delete {
        /// Jail name
        #[arg(long)]
        jail: String,
        /// .desktop file name (e.g. firefox.desktop or pj-xray-firefox.desktop)
        desktop_file: String,
    },
    /// List installed desktop entries
    List {
        /// Filter by jail name
        #[arg(long)]
        jail: Option<String>,
    },
}

fn main() -> Result<()> {
    // If not running as root, re-exec ourselves via `sudo -E`.
    //
    // `-E` (preserve environment) lets the child inherit the caller's
    // full environment, so GUI variables (DISPLAY, XAUTHORITY,
    // DBUS_SESSION_BUS_ADDRESS, etc.) survive the privilege elevation.
    //
    // The `debian/postinst` sudoers file must include
    //     Defaults env_delete += "LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH ..."
    // so dangerous variables are stripped before reaching the root
    // process.  See the postinst script for the canonical list.
    if !nix::unistd::Uid::effective().is_root() {
        let args: Vec<String> = std::env::args().collect();
        let exe = std::env::current_exe()
            .context("Failed to get current executable path")?;

        eprintln!("Elevating privileges via sudo...");
        // We use `-E` (preserve env) PLUS `--preserve-env=PATH` to
        // override sudo's hard-coded `secure_path` replacement of
        // PATH.  Without the explicit preserve, sudo will silently
        // replace PATH with /usr/local/sbin:/usr/local/bin:... and
        // the user's toolchain (cargo, go, mise, ...) will be lost.
        //
        // Note: sudo's env_reset still hard-clears USER/LOGNAME/HOME/
        // MAIL/SHELL even with -E.  We rebuild those in
        // `launcher::spawn_app` from the real user info (which is
        // available via SUDO_UID/SUDO_USER) before exec'ing the user
        // command, so this is fine.
        let status = std::process::Command::new("sudo")
            .arg("-E")
            .arg("--preserve-env=PATH")
            .arg(exe)
            .args(&args[1..])
            .status()
            .context("Failed to execute sudo")?;

        std::process::exit(status.code().unwrap_or(1));
    }

    let cli = Cli::parse();

    // Initialize logging
    init_logging(cli.verbose);

    // Load configuration
    let mut config = config::Config::load()?;

    match cli.command {
        Commands::Jail { command } => match command {
            JailCommands::Create { name, socks5 } => {
                jail::create_jail(&name, &socks5, &mut config)?;
            }
            JailCommands::List => {
                jail::list_jails(&config)?;
            }
            JailCommands::Start { name } => {
                jail::start_jail(&name, &config)?;
            }
            JailCommands::Stop { name } => {
                jail::stop_jail(&name, &config)?;
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
                let jail_config = config.find_jail(&jail)
                    .ok_or_else(|| anyhow::anyhow!("Jail '{}' not found", jail))?;

                desktop::desktop_install_from_file(jail_config, &from)?;
            }
            DesktopCommands::Delete { jail, desktop_file } => {
                let jail_config = config.find_jail(&jail)
                    .ok_or_else(|| anyhow::anyhow!("Jail '{}' not found", jail))?;

                desktop::desktop_uninstall_from_file(jail_config, &desktop_file)?;
            }
            DesktopCommands::List { jail } => {
                let files = desktop::list_desktop_files(jail.as_deref())?;

                if files.is_empty() {
                    println!("No proxy-jail desktop entries found.");
                } else {
                    println!("Installed proxy-jail desktop entries:");
                    for file in files {
                        println!("  {:?}", file);
                    }
                }
            }
        },
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

    let filter = EnvFilter::from_default_env()
        .add_directive(level.into());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();
}
