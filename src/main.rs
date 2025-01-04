use clap::Parser;
use rand::RngCore;
use shifter::{
    cli::{self, ShifterArgs},
    file_format::{
        self, DecryptedShifterFile, EncryptedShifterFile, ShifterFileDecryptError,
        ShifterFileParseError,
    },
};
use std::{
    fs::{rename, File},
    process::exit,
};

fn main() {
    let args = ShifterArgs::parse();
    match args.mode {
        cli::Mode::Encrypt {
            file,
            password,
            outfile,
        } => encrypt(file, &Vec::from(password), outfile),
        cli::Mode::Decrypt { file, password } => decrypt(file, &Vec::from(password)),
    }
}

fn decrypt(filename: String, password: &[u8]) {
    let encrypted_file = File::open(&filename).unwrap_or_else(|err| {
        eprintln!("Could not open file: {filename}");
        eprintln!("Error: {err:?}");
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
    let out = File::open(generate_decrypted_filename()).unwrap_or_else(|err| {
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

        Err(ShifterFileDecryptError::InvalidFilenameUtf8 {
            err: _,
            file_contents: _,
        }) => {
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

fn encrypt(filename: String, password: &[u8], output_filename: Option<String>) {
    let contents = File::open(&filename).unwrap_or_else(|err| {
        eprintln!("Could not open file: {filename}");
        eprintln!("Error: {err:?}");
        exit(1);
    });
    let df = DecryptedShifterFile { filename, contents };

    let out_name = output_filename.unwrap_or_else(generate_encrypted_filename);
    let out = File::open(generate_decrypted_filename()).unwrap_or_else(|err| {
        eprintln!("Could not open output file");
        eprintln!("Error: {err:?}");
        exit(1);
    });
    df.encrypt(password, out).unwrap_or_else(|err| {
        eprintln!("I/O error occurred: {:?}", err);
        exit(1);
    });

    println!("Encrypted file written to: {:?}", out_name)
}

fn generate_decrypted_filename() -> String {
    format!("decrypted-file-{:?}", rand::thread_rng().next_u32())
}

fn generate_encrypted_filename() -> String {
    format!("encrypted-{:?}.shifted", rand::thread_rng().next_u32())
}
