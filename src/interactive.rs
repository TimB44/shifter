use std::{
    error::Error,
    fs::{exists, read, File},
    io::{self, Read},
    process::exit,
};

use inquire::{
    validator::{StringValidator, Validation},
    CustomUserError, Password, Select, Text,
};

use crate::{
    decrypt, encrypt,
    file_format::SHIFTER_FILE_MAGIC_NUMBER,
    passphrase_generator::{
        generate_passphrase, DEFAULT_PASSPHRASE_LENGTH, MAX_PASSPHRASE_LENGTH,
        MIN_PASSPHRASE_LENGTH,
    },
};
//TODO:
// - When searching for file passwords give autocomplete

pub fn run_iteractive() -> io::Result<()> {
    const ENCRYPT: &str = "Encrypt";
    const DECRYPT: &str = "Decrypt";
    let mode = Select::new("Select a mode", vec![ENCRYPT, DECRYPT])
        .with_vim_mode(true)
        .prompt()
        .unwrap_or_else(|err| {
            eprintln!("Error: {err}");
            exit(1);
        });

    match mode {
        ENCRYPT => {
            let filename = Text::new("Enter file to encrypt")
                .with_validator(FileValidator)
                .prompt()
                .unwrap_or_else(|err| {
                    eprintln!("Error: {err}");
                    exit(1);
                });

            let password = get_password(true)?;
            encrypt(filename.clone(), &password, None);
        }
        DECRYPT => {
            let filename = Text::new("Enter file to encrypt")
                .with_validator(FileValidator)
                .with_validator(ShifterFileMagicNumberValidtor)
                .prompt()
                .unwrap_or_else(|err| {
                    eprintln!("Error: {err}");
                    exit(1);
                });

            let password = get_password(false)?;
            decrypt(filename.clone(), &password);
        }
        _ => unreachable!(),
    };
    Ok(())
}

fn get_password(generate_as_option: bool) -> io::Result<Vec<u8>> {
    const FROM_FILE: &str = "From File";
    const TEXT: &str = "Enter as Text";
    const AUTO_GEN: &str = "Auto Generate";
    let mut options = Vec::with_capacity(3);
    options.push(FROM_FILE);
    options.push(TEXT);
    if generate_as_option {
        options.push(AUTO_GEN);
    }

    match Select::new("Password Options", options)
        .with_vim_mode(true)
        .prompt()
        .unwrap_or_else(|err| {
            eprintln!("Error: {err}");
            exit(1);
        }) {
        FROM_FILE => {
            let filename = Text::new("Enter File With Password")
                .with_validator(FileValidator)
                .prompt()
                .unwrap_or_else(|err| {
                    eprintln!("Error: {err}");
                    exit(1);
                });
            read(&filename)
        }
        TEXT => Ok(Password::new("Enter Password")
            .with_validator(move |password: &str| {
                if password.is_empty() {
                    return Ok(Validation::Invalid("Password can not be empty".into()));
                }
                Ok(Validation::Valid)
            })
            .prompt()
            .unwrap_or_else(|err| {
                eprintln!("Error: {err}");
                exit(1);
            })
            .into_bytes()),
        AUTO_GEN => {
            let length: usize = Text::new("Enter Passphrase Length")
            .with_default(&DEFAULT_PASSPHRASE_LENGTH.to_string())
            .with_validator(move |count: &str| {
                if !count.chars().all(|c| c.is_ascii_digit()) {
                    return Ok(Validation::Invalid("Must enter number".into()));
                }
                match count.parse::<usize>() {
                    Ok(length) if length < MIN_PASSPHRASE_LENGTH && length > MAX_PASSPHRASE_LENGTH => Ok(Validation::Invalid(format!("Passphrase Lenght must be in range [{MIN_PASSPHRASE_LENGTH}, {MAX_PASSPHRASE_LENGTH}]").into())),
                    Ok(_) =>  {
                        Ok(Validation::Valid)
                    }
                    Err(err) => Ok(Validation::Invalid(format!("Error parsing number: {err}").into())),
                }
            }).prompt().unwrap_or_else(|err| {
                    eprintln!("Error: {err}");
                    exit(1);
                }).parse().expect("validator should prevent non number inptus");

            let password = generate_passphrase(Some(length));
            println!("Generate Passphrase: {password}");
            Ok(password.into_bytes())
        }
        _ => unreachable!(),
    }
}

#[derive(Clone)]
struct FileValidator;

impl StringValidator for FileValidator {
    fn validate(&self, filename: &str) -> Result<Validation, CustomUserError> {
        Ok(if exists(filename)? {
            Validation::Valid
        } else {
            Validation::Invalid(format!("Could not find file: {filename}").into())
        })
    }
}

#[derive(Clone)]
struct ShifterFileMagicNumberValidtor;

impl StringValidator for ShifterFileMagicNumberValidtor {
    fn validate(&self, filename: &str) -> Result<Validation, CustomUserError> {
        let mut file = File::open(filename).map_err(|err| Box::new(err))?;
        let mut file_magic_number = [0; SHIFTER_FILE_MAGIC_NUMBER.len()];
        file.read_exact(file_magic_number.as_mut_slice())?;
        if SHIFTER_FILE_MAGIC_NUMBER != &file_magic_number {
            Ok(Validation::Invalid(
                "Given file not in correct format".into(),
            ))
        } else {
            Ok(Validation::Valid)
        }
    }
}
