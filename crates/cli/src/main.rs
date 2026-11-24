//! `passguardian`: the command-line client.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use passguardian_cli::session::default_home;
use passguardian_cli::{Cli, CliError, Item};
use passguardian_core::generator::{generate_password, os_random_u32, CharClasses};

#[derive(Parser)]
#[command(
    name = "passguardian",
    version,
    about = "PassGuardian password manager"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create an account on a server and log this device in.
    Register {
        /// Server address, for example `https://pass.example.org`.
        #[arg(long, env = "PASSGUARDIAN_SERVER")]
        server: String,
        /// Account email.
        #[arg(long)]
        email: String,
        /// Name shown for this device.
        #[arg(long, default_value = "cli")]
        device: String,
    },
    /// Log this device in to an existing account.
    Login {
        /// Server address.
        #[arg(long, env = "PASSGUARDIAN_SERVER")]
        server: String,
        /// Account email.
        #[arg(long)]
        email: String,
        /// Name shown for this device.
        #[arg(long, default_value = "cli")]
        device: String,
    },
    /// Forget the session of this device.
    Logout,
    /// Add an item.
    Add {
        /// Display name.
        name: String,
        /// User name.
        #[arg(long, default_value = "")]
        username: String,
        /// Site address.
        #[arg(long, default_value = "")]
        url: String,
        /// Notes.
        #[arg(long, default_value = "")]
        notes: String,
        /// Generate the password instead of asking for it.
        #[arg(long)]
        generate: bool,
        /// Length of a generated password.
        #[arg(long, default_value_t = 24)]
        length: usize,
    },
    /// List the items.
    List,
    /// Show one item (by identifier or name).
    Get {
        /// Identifier or name.
        item: String,
        /// Print only the password, for scripts.
        #[arg(long)]
        password_only: bool,
    },
    /// Delete an item (by identifier or name).
    Delete {
        /// Identifier or name.
        item: String,
    },
    /// Show the vault revision and the number of items.
    Status,
    /// Print a random password.
    Generate {
        /// Length.
        #[arg(long, default_value_t = 24)]
        length: usize,
        /// Leave out symbols.
        #[arg(long)]
        no_symbols: bool,
    },
}

fn master_password(confirm: bool) -> Result<String, CliError> {
    if let Ok(password) = std::env::var("PASSGUARDIAN_PASSWORD") {
        return Ok(password);
    }
    let first = rpassword::prompt_password("Master password: ")?;
    if confirm && rpassword::prompt_password("Repeat master password: ")? != first {
        return Err(CliError::Input("the passwords differ".into()));
    }
    Ok(first)
}

fn random_password(length: usize, symbols: bool) -> Result<String, CliError> {
    let classes = CharClasses {
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols,
    };
    generate_password(&mut os_random_u32, length, &classes)
        .map_err(|e| CliError::Input(e.to_string()))
}

fn run(args: Args) -> Result<(), CliError> {
    let cli = Cli::new(default_home());
    match args.command {
        Command::Register {
            server,
            email,
            device,
        } => {
            cli.register(&server, &email, &master_password(true)?, &device)?;
            println!("Account created and device logged in.");
        }
        Command::Login {
            server,
            email,
            device,
        } => {
            cli.login(&server, &email, &master_password(false)?, &device)?;
            println!("Logged in.");
        }
        Command::Logout => {
            cli.logout()?;
            println!("Logged out.");
        }
        Command::Add {
            name,
            username,
            url,
            notes,
            generate,
            length,
        } => {
            let master = master_password(false)?;
            let password = if generate {
                random_password(length, true)?
            } else {
                rpassword::prompt_password("Item password: ")?
            };
            let id = cli.add(
                &master,
                &Item {
                    name,
                    username,
                    password,
                    url,
                    notes,
                },
            )?;
            println!("{id}");
        }
        Command::List => {
            for entry in cli.list(&master_password(false)?)? {
                println!("{}  {}  {}", entry.id, entry.item.name, entry.item.username);
            }
        }
        Command::Get {
            item,
            password_only,
        } => {
            let entry = cli.get(&master_password(false)?, &item)?;
            if password_only {
                println!("{}", entry.item.password);
            } else {
                println!("id:       {}", entry.id);
                println!("name:     {}", entry.item.name);
                println!("username: {}", entry.item.username);
                println!("password: {}", entry.item.password);
                println!("url:      {}", entry.item.url);
                println!("notes:    {}", entry.item.notes);
            }
        }
        Command::Delete { item } => {
            let id = cli.delete(&master_password(false)?, &item)?;
            println!("Deleted {id}.");
        }
        Command::Status => {
            let (revision, count) = cli.status(&master_password(false)?)?;
            println!("revision {revision}, {count} item(s)");
        }
        Command::Generate { length, no_symbols } => {
            println!("{}", random_password(length, !no_symbols)?);
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
