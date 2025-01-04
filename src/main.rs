use clap::Parser;
use rand::RngCore;
use shifter::{
    cli::{self, ShifterArgs},
    file_format::{self, EncryptedShifterFile, ShifterFileDecryptError, ShifterFileParseError},
};
use std::{
    fs::{rename, File},
    process::exit,
};

fn main() {
    let args = ShifterArgs::parse();
    match args.mode {
        cli::Mode::Encrypt { file, password } => encrypt(file, &Vec::from(password)),
        cli::Mode::Decrypt { file, password } => decrypt(file, &Vec::from(password)),
    }
}

fn decrypt(file: String, password: &[u8]) {
    let encrypted_file = File::open(&file).unwrap_or_else(|err| {
        eprintln!("Could not open file: {file}");
        eprintln!("Error: {err:?}");
        exit(1);
    });

    println!("Parsing file: {file}");
    let mut parsed_file = match EncryptedShifterFile::load_from_file(encrypted_file) {
        Ok(pf) => pf,
        Err(ShifterFileParseError::ReadError(err)) => {
            eprintln!("Error reading encrypted file: {err:?}");
            exit(1);
        }
        Err(ShifterFileParseError::IncorrectMagicNumber {
            actual_magic_number: _,
        }) => {
            eprintln!("Error: Incorrect magic number. Are you sure this is a encrypted file?");
            exit(1);
        }
        Err(ShifterFileParseError::IncorrectVersionNumber { actual_verion: _ }) => {
            eprintln!("Error: File format version outside of supported range");
            exit(1);
        }
    };

    println!("Decrypting");
    let temp_name = generate_generic_filename();
    let out = File::open(generate_generic_filename()).unwrap_or_else(|err| {
        eprintln!("Could not open output file");
        eprintln!("Error: {err:?}");
        exit(1);
    });

    let file_format::DecryptedShifterFile {
        filename,
        contents: _,
    } = match parsed_file.decrypt(password, out) {
        Ok(df) => df,
        Err(ShifterFileDecryptError::HmacTagIncorrect {
            expected_tag: _,
            calcuated_tag: _,
        }) => {
            eprintln!("Error: File tag mismatch. This is likely due to an incorrect password or a corrupted file.");
            exit(1);
        }

        Err(ShifterFileDecryptError::InvalidFileNameLength {
            filename: _,
            file_contents: _,
        }) => {
            eprintln!("Error: The filename extracted from the encrypted file exceeds the maximum allowed length. Writing to `{}` instead.", temp_name);
            exit(1);
        }

        Err(ShifterFileDecryptError::InvalidFilenameUtf8 { err, file_contents }) => {
            eprintln!("Error: The filename extracted from the encrypted file is not valid UTF-8. Writing to `{}` instead.", temp_name);
            exit(1);
        }

        Err(ShifterFileDecryptError::IOError(err)) => {
            eprintln!("I/O error occurred: {:?}", err);
            exit(1);
        }
        Err(ShifterFileDecryptError::NoNullByte { file_contents: _ }) => {
            eprintln!(
                "Error: No filename found in the encrypted file. Writing to `{}` instead.",
                temp_name
            );
            exit(1);
        }
    };

    rename(&temp_name, &filename).unwrap_or_else(|err| {
        eprintln!("Could not rename file to: {filename:?}");
        eprintln!("Error: {err:?}");
        eprintln!("File written to: {temp_name:?}");
        exit(1);
    });
    eprintln!("File written to: {filename:?}");
}

fn encrypt(file: String, password: &[u8]) {
    todo!()
}

fn generate_generic_filename() -> String {
    format!("decrypted-file-{:?}", rand::thread_rng().next_u32())
}
