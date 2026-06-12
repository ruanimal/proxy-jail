use anyhow::Result;
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
}

#[derive(Subcommand)]
enum JailCommands {
    /// Create a new jail
    Create {
        /// Jail name
        name: String,
        /// SOCKS5 proxy address (host:port)
        #[arg(long)]
        socks5: String,
    },
    /// List all jails
    List,
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
    /// Run an application in a jail
    Run {
        /// Jail name
        jail: String,
        /// Command to run
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Stop an application in a jail
    Stop {
        /// Jail name
        jail: String,
        /// Application name
        app: String,
    },
    /// Manage desktop entries
    Desktop {
        #[command(subcommand)]
        command: DesktopCommands,
    },
}

#[derive(Subcommand)]
enum DesktopCommands {
    /// Install a desktop entry
    Install {
        /// Jail name
        jail: String,
        /// Application command
        app: String,
    },
    /// Uninstall a desktop entry
    Uninstall {
        /// Jail name
        jail: String,
        /// Application command
        app: String,
    },
    /// List installed desktop entries
    List {
        /// Filter by jail name
        #[arg(long)]
        jail: Option<String>,
    },
}

fn main() -> Result<()> {
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
            JailCommands::Stop { name } => {
                jail::stop_jail(&name, &config)?;
            }
            JailCommands::Delete { name } => {
                jail::delete_jail(&name, &mut config)?;
            }
        },
        Commands::App { command } => match command {
            AppCommands::Run { jail, command } => {
                if command.is_empty() {
                    anyhow::bail!("No command specified");
                }
                let cmd = &command[0];
                let args = &command[1..];
                jail::run_app(&jail, cmd, args, &config)?;
            }
            AppCommands::Stop { jail, app } => {
                jail::stop_app(&jail, &app, &config)?;
            }
            AppCommands::Desktop { command } => match command {
                DesktopCommands::Install { jail, app } => {
                    let jail_config = config.find_jail(&jail)
                        .ok_or_else(|| anyhow::anyhow!("Jail '{}' not found", jail))?;

                    let app_config = jail_config.apps.iter()
                        .find(|a| a.command == app)
                        .ok_or_else(|| anyhow::anyhow!("Application '{}' not found in jail '{}'", app, jail))?;

                    desktop::desktop_install(jail_config, app_config)?;
                }
                DesktopCommands::Uninstall { jail, app } => {
                    let jail_config = config.find_jail(&jail)
                        .ok_or_else(|| anyhow::anyhow!("Jail '{}' not found", jail))?;

                    let app_config = jail_config.apps.iter()
                        .find(|a| a.command == app)
                        .ok_or_else(|| anyhow::anyhow!("Application '{}' not found in jail '{}'", app, jail))?;

                    desktop::desktop_uninstall(jail_config, app_config)?;
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
