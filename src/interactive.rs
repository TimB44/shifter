use std::path::{Path, MAIN_SEPARATOR};
use std::{
    fs::{read, read_dir, File},
    io::{self, Read},
    path::MAIN_SEPARATOR_STR,
    process::exit,
};

use fuzzy_matcher::{skim::SkimMatcherV2, FuzzyMatcher};
use inquire::Confirm;
use inquire::{
    validator::{StringValidator, Validation},
    Autocomplete, CustomUserError, Password, Select, Text,
};

use crate::{
    decrypt, encrypt,
    file_format::SHIFTER_FILE_MAGIC_NUMBER,
    passphrase_generator::{
        generate_passphrase, DEFAULT_PASSPHRASE_LENGTH, MAX_PASSPHRASE_LENGTH,
        MIN_PASSPHRASE_LENGTH,
    },
};
use crate::{generate_encrypted_filename, wipe_file};

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
            let input_filename = Text::new("Enter file to encrypt")
                .with_validator(FileValidator)
                .with_autocomplete(FileAutocomplete::default())
                .prompt()
                .unwrap_or_else(|err| {
                    eprintln!("Error: {err}");
                    exit(1);
                });

            let password = get_password(true)?;
            let output_filename = Text::new("Enter filename")
                .with_autocomplete(FileAutocomplete::default())
                .with_default(&generate_encrypted_filename())
                .prompt()
                .unwrap_or_else(|err| {
                    eprintln!("Error: {err}");
                    exit(1);
                });
            encrypt(input_filename.clone(), &password, Some(output_filename));
            ask_wipe_input_file(&input_filename);
        }
        DECRYPT => {
            let input_filename = Text::new("Enter file to encrypt")
                .with_validator(FileValidator)
                .with_validator(ShifterFileMagicNumberValidtor)
                .with_autocomplete(FileAutocomplete::default())
                .prompt()
                .unwrap_or_else(|err| {
                    eprintln!("Error: {err}");
                    exit(1);
                });

            let password = get_password(false)?;
            decrypt(input_filename.clone(), &password);
            ask_wipe_input_file(&input_filename);
        }
        _ => unreachable!(),
    };
    Ok(())
}

fn ask_wipe_input_file(input_filename: &str) {
    if Confirm::new(&format!("Delete file {input_filename}"))
        .with_default(true)
        .prompt()
        .unwrap_or_else(|err| {
            eprintln!("Error: {err}");
            exit(1);
        })
    {
        wipe_file(input_filename).unwrap_or_else(|err| {
            eprintln!("Error: {err}");
            exit(1);
        })
    }
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
                .with_autocomplete(FileAutocomplete::default())
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
                    Ok(length) if !(MIN_PASSPHRASE_LENGTH..=MAX_PASSPHRASE_LENGTH).contains(&length) => Ok(Validation::Invalid(format!("Passphrase Lenght must be in range [{MIN_PASSPHRASE_LENGTH}, {MAX_PASSPHRASE_LENGTH}]").into())),
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
    fn validate(&self, input: &str) -> Result<Validation, CustomUserError> {
        let path = Path::new(input);
        let validation = if !path.exists() {
            Validation::Invalid(format!("Could not find file: {input}").into())
        } else if !path.is_file() {
            Validation::Invalid(format!("Expected file, found directory: {input}").into())
        } else {
            Validation::Valid
        };

        Ok(validation)
    }
}

#[derive(Clone)]
struct ShifterFileMagicNumberValidtor;

impl StringValidator for ShifterFileMagicNumberValidtor {
    fn validate(&self, filename: &str) -> Result<Validation, CustomUserError> {
        fn try_validate(filename: &str) -> io::Result<Validation> {
            let mut file = File::open(filename)?;
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

        Ok(try_validate(filename).unwrap_or_else(|err| {
            Validation::Invalid(format!("Error reading '{}': {}", filename, err).into())
        }))
    }
}

//TOOD: possibly improve performance with caching
#[derive(Clone, Default)]
struct FileAutocomplete {
    prev_suggestions: Vec<String>,
    last_chosen_suggestion: Option<usize>,
}

impl FileAutocomplete {
    fn get_filename_parts(filename: &str) -> (&str, &str) {
        match filename.chars().rev().position(|c| c == MAIN_SEPARATOR) {
            Some(rev_i) => {
                let i = filename.chars().count() - rev_i - 1;
                (&filename[..i + 1], &filename[i + 1..])
            }
            None => ("", filename),
        }
    }

    fn list_matching_files(dir: &str, pattern: &str) -> io::Result<Vec<String>> {
        let names: Vec<_> = read_dir(if dir.is_empty() { "." } else { dir })?
            .filter_map(Result::ok)
            .map(|dir_entry| {
                dir_entry.file_name().to_string_lossy().into_owned()
                    + if dir_entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                        MAIN_SEPARATOR_STR
                    } else {
                        ""
                    }
            })
            .collect();

        let matcher = SkimMatcherV2::default();
        let mut search_results: Vec<_> = names
            .into_iter()
            .filter_map(|name| {
                matcher
                    .fuzzy_match(&name, pattern)
                    .map(|score| (name, score))
            })
            .collect();

        search_results.sort_by(|(lhs_str, lhs_similarity), (rhs_str, rhs_similarity)| {
            rhs_similarity
                .cmp(lhs_similarity)
                // TODO: sort by alpha first then others also to_lowercase is bad
                .then_with(|| lhs_str.to_lowercase().cmp(&rhs_str.to_lowercase()))
        });

        Ok(search_results.into_iter().map(|(name, _)| name).collect())
    }
}

impl Autocomplete for FileAutocomplete {
    fn get_suggestions(&mut self, input: &str) -> Result<Vec<String>, CustomUserError> {
        let (dir, filename) = FileAutocomplete::get_filename_parts(input);
        let suggestions: Vec<String> = FileAutocomplete::list_matching_files(dir, filename)
            .unwrap_or_default()
            .into_iter()
            .collect();

        self.prev_suggestions = suggestions.clone();
        Ok(suggestions)
    }

    fn get_completion(
        &mut self,
        input: &str,
        highlighted_suggestion: Option<String>,
    ) -> Result<inquire::autocompletion::Replacement, CustomUserError> {
        let (dir, _) = Self::get_filename_parts(input);
        let suggestion = if let Some(highlighted_suggestion) = highlighted_suggestion {
            self.last_chosen_suggestion = Some(
                self.prev_suggestions
                    .iter()
                    .position(|s| *s == highlighted_suggestion)
                    .expect("highlighted_suggestion should be in previous suggestions"),
            );
            Some(highlighted_suggestion)
        } else if !self.prev_suggestions.is_empty() {
            let next_suggestion = self
                .last_chosen_suggestion
                .map(|n| (n + 1) % self.prev_suggestions.len())
                .unwrap_or(0);
            self.last_chosen_suggestion = Some(next_suggestion);
            Some(self.prev_suggestions[next_suggestion].clone())
        } else {
            None
        };

        Ok(suggestion.map(|mut file| {
            file.insert_str(0, dir);
            if matches!(file.chars().last(), Some(MAIN_SEPARATOR)) {
                file.pop();
            }
            file
        }))
    }
}
