use std::{fs::read, process::exit};

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "shifter")]
#[command(about,version, long_about = None)]
pub struct ShifterArgs {
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Debug, Subcommand)]
pub enum Mode {
    Encrypt {
        #[arg(short, long)]
        file: String,

        #[clap(flatten)]
        password: Password,

        #[arg(short, long)]
        outfile: Option<String>,
    },

    Decrypt {
        #[arg(short, long)]
        file: String,

        #[clap(flatten)]
        password: Password,
    },
}

#[derive(Debug, clap::Args)]
#[group(required = true, multiple = false)]
pub struct Password {
    /// Give password directly as argument  
    #[clap(short, long)]
    password_file: Option<String>,

    /// Load password from file
    #[clap(short, long)]
    password: Option<String>,
}

impl From<Password> for Vec<u8> {
    fn from(value: Password) -> Self {
        match (value.password, value.password_file) {
            (Some(password), None) => password.into_bytes(),

            (None, Some(password_file)) => read(&password_file).unwrap_or_else(|_| {
                eprintln!("Failed to load password file: {:?}", password_file);
                exit(1);
            }),

            (None, None) | (Some(_), Some(_)) => unreachable!(),
        }
    }
}
