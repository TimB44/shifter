use std::{fs::read, process::exit, usize};

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
    #[clap(visible_alias("e"))]
    Encrypt {
        #[arg(required = true)]
        file: String,

        #[clap(flatten)]
        password: OptionalPassword,

        #[arg(short, long)]
        outfile: Option<String>,
    },

    #[clap(visible_alias("d"))]
    Decrypt {
        #[arg(required = true)]
        file: String,

        #[clap(flatten)]
        password: RequiredPassword,
    },
}

#[derive(Debug, Clone, clap::Args)]
#[group(required = true, multiple = false)]
pub struct RequiredPassword {
    /// Load password from file
    #[clap(long)]
    password_file: Option<String>,

    /// Give password directly as argument  
    #[clap(short, long)]
    password: Option<String>,
}

impl From<RequiredPassword> for Vec<u8> {
    fn from(value: RequiredPassword) -> Self {
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

#[derive(Debug, Clone, clap::Args)]
#[group(multiple = false)]
pub struct OptionalPassword {
    /// Load password from file
    #[clap(long)]
    password_file: Option<String>,

    /// Give password directly as argument  
    #[clap(short, long)]
    password: Option<String>,

    /// Desired length of generated passphrase in words
    #[clap(short, long)]
    lengh: Option<usize>,
}

impl OptionalPassword {
    pub fn lengh(&self) -> Option<usize> {
        self.lengh
    }
}

impl From<OptionalPassword> for Option<Vec<u8>> {
    fn from(value: OptionalPassword) -> Self {
        match (value.password, value.password_file) {
            (Some(password), None) => Some(password.into_bytes()),

            (None, Some(password_file)) => Some(read(&password_file).unwrap_or_else(|_| {
                eprintln!("Failed to load password file: {:?}", password_file);
                exit(1);
            })),
            (None, None) => None,
            (Some(_), Some(_)) => unreachable!(),
        }
    }
}
