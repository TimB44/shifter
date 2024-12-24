use std::{
    env::temp_dir,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    string::FromUtf8Error,
};

use rand::RngCore;
use thiserror::Error;

use crate::crypto::{chacha20, hmac_sha256, pbkdf2, U256};

const SHIFTER_FILE_MAGIC_NUMBER: &[u8; 4] = b"SHFT";
const MIN_SUPPORTED_VERSION_NUMBER: u8 = 1;
const MAX_SUPPORTED_VERSION_NUMBER: u8 = 1;
const MAX_FILENAME_LENGTH: usize = 255;
const CIPHERTEXT_OFFSET: u64 = 101;

// TODO: Find a good number which balances speed and security
const PBKDF2_ITERATIONS: u32 = 1_000;

/// This module contains the code the code to create, read and write shifter files  

pub struct ShifterFile {
    version_number: u8,
    hmac_tag: U256,
    hmac_salt: U256,
    chacha_salt: U256,
    file: File,
}

pub struct DecryptedShifterFile {
    pub filename: String,
    pub contents: File,
}

#[derive(Error, Debug)]
pub enum ShifterFileParseError {
    #[error("error while reading file")]
    ReadError(#[from] io::Error),

    #[error("invalid magic number (expected {SHIFTER_FILE_MAGIC_NUMBER:?}) found {actual_magic_number:?}")]
    IncorrectMagicNumber { actual_magic_number: [u8; 4] },

    #[error("invalid version number (expected number in range [{MIN_SUPPORTED_VERSION_NUMBER},{MAX_SUPPORTED_VERSION_NUMBER} ] found {actual_verion:?}")]
    IncorrectVersionNumber { actual_verion: u8 },
}

#[derive(Error, Debug)]
pub enum ShifterFileDecryptError {
    #[error("invalid magic number (expected {expected_tag:?}) calculated {calcuated_tag:?}")]
    HmacTagIncorrect {
        expected_tag: U256,
        calcuated_tag: U256,
    },

    #[error("original filename length {length} outside of valid range [1, {MAX_FILENAME_LENGTH}]")]
    InvalidFileNameLength {
        length: usize,
        filename: String,
        file_contents: File,
    },

    #[error("filename is not invalid UTF8")]
    InvalidFilenameUtf8 {
        #[source]
        err: FromUtf8Error,
        file_contents: File,
    },

    #[error("error writing plaintext file")]
    IOError(#[from] io::Error),

    #[error("plaintext missing null byte seperator between filename and content")]
    NoNullByte,
}

impl ShifterFile {
    pub fn load_from_file(mut file: File) -> Result<ShifterFile, ShifterFileParseError> {
        let mut magic_number = [0; SHIFTER_FILE_MAGIC_NUMBER.len()];
        file.read_exact(&mut magic_number)?;
        if magic_number != *SHIFTER_FILE_MAGIC_NUMBER {
            return Err(ShifterFileParseError::IncorrectMagicNumber {
                actual_magic_number: magic_number,
            });
        }

        let mut version_number = [0];
        file.read_exact(&mut version_number)?;
        let version_number = version_number[0];
        if version_number < MIN_SUPPORTED_VERSION_NUMBER
            || version_number > MAX_SUPPORTED_VERSION_NUMBER
        {
            return Err(ShifterFileParseError::IncorrectVersionNumber {
                actual_verion: version_number,
            });
        }

        let mut hmac_tag = [0; 32];
        file.read_exact(&mut hmac_tag)?;

        let mut hmac_salt = [0; 32];
        file.read_exact(&mut hmac_salt)?;

        let mut chacha_salt = [0; 32];
        file.read_exact(&mut chacha_salt)?;

        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext)?;

        Ok(ShifterFile {
            version_number,
            hmac_tag,
            hmac_salt,
            chacha_salt,
            file,
        })
    }

    pub fn decrypt(
        &mut self,
        password: &[u8],
    ) -> Result<DecryptedShifterFile, ShifterFileDecryptError> {
        // Compute both derived keys in parallel
        let (hmac_dk, chacha_dk) = rayon::join(
            || {
                let mut buf = [0; 32];
                pbkdf2(password, &self.hmac_salt, PBKDF2_ITERATIONS, &mut buf);
                buf
            },
            || {
                let mut buf = [0; 32];
                pbkdf2(password, &self.hmac_salt, PBKDF2_ITERATIONS, &mut buf);
                buf
            },
        );

        self.file.seek(SeekFrom::Start(CIPHERTEXT_OFFSET))?;

        let mut ciphertext = Vec::new();
        self.file.read_to_end(&mut ciphertext)?;
        let tag = hmac_sha256(&hmac_dk, &mut ciphertext);
        if self.hmac_tag != tag {
            return Err(ShifterFileDecryptError::HmacTagIncorrect {
                expected_tag: self.hmac_tag,
                calcuated_tag: tag,
            });
        }

        let mut rand = rand::thread_rng();
        let mut nonce = [0; 12];
        rand.fill_bytes(&mut nonce);

        chacha20(&chacha_dk, &nonce, &mut ciphertext, 0);
        let plaintext = ciphertext;

        // The first null byte is the seperator between the filename and filecontents
        let split = plaintext
            .iter()
            .position(|&b| b == 0)
            .ok_or(ShifterFileDecryptError::NoNullByte)?;

        let mut file_contents =
            File::open(temp_dir().join(rand::thread_rng().next_u64().to_string()))?;
        file_contents.write_all(&plaintext[split..])?;

        let filename = match String::from_utf8(plaintext[0..split].to_vec()) {
            Ok(filename) => filename,
            Err(err) => {
                return Err(ShifterFileDecryptError::InvalidFilenameUtf8 { err, file_contents })
            }
        };

        if split < 1 || split > MAX_FILENAME_LENGTH {
            return Err(ShifterFileDecryptError::InvalidFileNameLength {
                length: split,
                filename,
                file_contents,
            });
        }

        return Ok(DecryptedShifterFile {
            filename,
            contents: file_contents,
        });
    }

    pub fn version_number(&self) -> u8 {
        self.version_number
    }

    pub fn hmac_tag(&self) -> [u8; 32] {
        self.hmac_tag
    }

    pub fn hmac_salt(&self) -> [u8; 32] {
        self.hmac_salt
    }

    pub fn chacha_salt(&self) -> [u8; 32] {
        self.chacha_salt
    }
}
