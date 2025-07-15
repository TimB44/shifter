//TODO: use tempfile create
use std::{
    fs::{remove_file, rename, File, OpenOptions},
    io::{self, prelude::*},
    process::exit,
};

use file_format::{
    DecryptedShifterFile, EncryptedShifterFile, ShifterFileDecryptError, ShifterFileParseError,
};
use rand::RngCore;

pub mod cli;
pub mod crypto;
pub mod file_format;
pub mod interactive;
pub mod passphrase_generator;

pub fn decrypt(filename: String, password: &[u8]) {
    let encrypted_file = File::open(&filename).unwrap_or_else(|err| {
        eprintln!("Could not open file: {filename}");
        eprintln!("Error: {err}");
        exit(1);
    });

    println!("Parsing file: {filename}");
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
    let temp_name = generate_decrypted_filename();
    let out = File::create(&temp_name).unwrap_or_else(|err| {
        eprintln!("Could not open output file");
        eprintln!("Error: {err:?}");
        exit(1);
    });

    let DecryptedShifterFile {
        filename,
        contents: _,
    } = match parsed_file.decrypt(password, out) {
        Ok(df) => df,
        Err(ShifterFileDecryptError::HmacTagIncorrect {
            expected_tag: _,
            calcuated_tag: _,
        }) => {
            eprintln!("Error: File tag mismatch. This is likely due to an incorrect password or a corrupted file.");
            remove_file(temp_name).expect("Could not remove temp file");
            exit(1);
        }

        Err(ShifterFileDecryptError::InvalidFileNameLength {
            filename: _,
            file_contents: _,
        }) => {
            eprintln!("Error: The filename extracted from the encrypted file exceeds the maximum allowed length. Writing to `{}` instead.", temp_name);
            exit(1);
        }

        Err(ShifterFileDecryptError::InvalidFilenameUtf8 {
            err: _,
            file_contents: _,
        }) => {
            eprintln!("Error: The filename extracted from the encrypted file is not valid UTF-8. Writing to `{}` instead.", temp_name);
            exit(1);
        }

        Err(ShifterFileDecryptError::IOError(err)) => {
            eprintln!("I/O error occurred: {}", err);
            remove_file(temp_name).expect("Could not remove temp file");
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
        eprintln!("Could not rename file to: {filename}");
        eprintln!("Error: {err}");
        eprintln!("File written to: {temp_name}");
        exit(1);
    });

    println!("File written to: {filename}");
}

pub fn encrypt(filename: String, password: &[u8], output_filename: Option<String>) {
    let contents = File::open(&filename).unwrap_or_else(|err| {
        eprintln!("Could not open file: {filename}");
        eprintln!("Error: {err}");
        exit(1);
    });
    let mut df = DecryptedShifterFile { filename, contents };

    let out_name = output_filename.unwrap_or_else(generate_encrypted_filename);
    let out = File::create(&out_name).unwrap_or_else(|err| {
        eprintln!("Could not create output file");
        eprintln!("Error: {err:?}");
        exit(1);
    });
    df.encrypt(password, out).unwrap_or_else(|err| {
        eprintln!("I/O error occurred: {:?}", err);
        exit(1);
    });

    println!("Encrypted file written to: {:?}", out_name)
}

pub fn generate_decrypted_filename() -> String {
    format!("decrypted-file-{:?}", rand::thread_rng().next_u32())
}

pub fn generate_encrypted_filename() -> String {
    format!("encrypted-{:?}.shifted", rand::thread_rng().next_u32())
}

//TODO: test function
pub fn wipe_file(filename: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).read(true).open(filename)?;
    let mut bytes_left = file.metadata()?.len();
    const BUF_SIZE: usize = 2usize.pow(10);
    let buf = [0; BUF_SIZE];
    while bytes_left >= BUF_SIZE as u64 {
        file.write_all(&buf)?;
        bytes_left -= BUF_SIZE as u64;
    }

    file.write_all(&buf[..bytes_left as usize])?;
    file.sync_all()?;
    drop(file);
    remove_file(filename)?;

    Ok(())
}
