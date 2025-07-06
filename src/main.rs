use clap::Parser;
use shifter::{
    cli::{Mode, ShifterArgs},
    decrypt, encrypt,
    interactive::run_iteractive,
    wipe_file,
};

use std::process::exit;

fn main() {
    let args = ShifterArgs::parse();
    match args.mode {
        Mode::Interactive => run_iteractive(),
        Mode::Encrypt {
            file,
            password,
            outfile,
            delete,
        } => {
            let password = Vec::from(password);

            encrypt(file.clone(), &password, outfile);

            if delete {
                wipe_file(&file).unwrap_or_else(|err| {
                    eprintln!("Failed to delete: {file}");
                    eprintln!("Error: {err}");
                    exit(1);
                });
            }
        }

        Mode::Decrypt {
            file,
            password,
            delete,
        } => {
            decrypt(file.clone(), &Vec::from(password));

            if delete {
                wipe_file(&file).unwrap_or_else(|err| {
                    eprintln!("Failed to delete: {file}");
                    eprintln!("Error: {err}");
                    exit(1);
                });
            }
        }
    }
}
