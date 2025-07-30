use std::{fs::read, process::exit};

use clap::{Parser, Subcommand};
use styling::CLAP_STYLING;

use crate::passphrase_generator::generate_passphrase;

mod styling;

#[derive(Debug, Parser)]
#[command(name = "shifter")]
#[command(about,version, long_about = None)]
#[clap(styles = CLAP_STYLING)]
pub struct ShifterArgs {
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Debug, Subcommand)]
pub enum Mode {
    #[clap(visible_alias("e"))]
    Encrypt {
        // The file to be encrypted
        #[arg(required = true)]
        file: String,

        #[clap(flatten)]
        password: OptionalPassword,

        // Name of the encrypted file
        #[arg(short, long)]
        outfile: Option<String>,

        /// Delete the given file after encryption
        #[arg(short, long)]
        delete: bool,
    },

    #[clap(visible_alias("d"))]
    Decrypt {
        #[arg(required = true)]
        file: String,

        #[clap(flatten)]
        password: RequiredPassword,

        /// Delete the encrypted file after decryption
        #[arg(short, long)]
        delete: bool,
    },
    #[clap(visible_alias("i"))]
    Interactive,
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

    /// Desired length of generated passphrase measured in words
    #[clap(short, long)]
    length: Option<usize>,
}

impl From<OptionalPassword> for Vec<u8> {
    fn from(value: OptionalPassword) -> Self {
        match (value.password, value.password_file, value.length) {
            (Some(password), None, None) => password.into_bytes(),

            (None, Some(password_file), None) => read(&password_file).unwrap_or_else(|_| {
                eprintln!("Failed to load password file: {:?}", password_file);
                exit(1);
            }),

            (None, None, Some(_)) | (None, None, None) => {
                let passphrase = generate_passphrase(value.length).into_bytes();
                println!(
                    "Generated passphrase: {}",
                    core::str::from_utf8(&passphrase).unwrap()
                );
                passphrase
            }
            _ => unreachable!(),
        }
    }
}
