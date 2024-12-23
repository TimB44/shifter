use std::{
    fs::File,
    io::{self, BufReader, Read},
};

use thiserror::Error;

use crate::crypto::U256;

const SHIFTER_FILE_MAGIC_NUMBER: &[u8; 4] = b"SHFT";
const MIN_SUPPORTED_VERSION_NUMBER: u8 = 1;
const MAX_SUPPORTED_VERSION_NUMBER: u8 = 1;

/// This module contains the code the code to create, read and write shifter files  

pub struct ShifterFile {
    version_number: u8,
    hmac_tag: U256,
    hmac_salt: U256,
    chacha_salt: U256,

    // TODO: avoid loading the entire file into memory
    ciphertext: Vec<u8>,
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

impl ShifterFile {
    pub fn load_from_file(file: File) -> Result<ShifterFile, ShifterFileParseError> {
        let mut buf_reader = BufReader::new(file);
        let mut magic_number = [0; SHIFTER_FILE_MAGIC_NUMBER.len()];

        buf_reader.read_exact(&mut magic_number)?;

        if magic_number != *SHIFTER_FILE_MAGIC_NUMBER {
            return Err(ShifterFileParseError::IncorrectMagicNumber {
                actual_magic_number: magic_number,
            });
        }
        let mut version_number = [0];
        buf_reader.read_exact(&mut version_number)?;
        let version_number = version_number[0];
        if version_number < MIN_SUPPORTED_VERSION_NUMBER
            || version_number > MAX_SUPPORTED_VERSION_NUMBER
        {
            return Err(ShifterFileParseError::IncorrectVersionNumber {
                actual_verion: version_number,
            });
        }

        let mut hmac_tag = [0; 32];
        buf_reader.read_exact(&mut hmac_tag)?;

        let mut hmac_salt = [0; 32];
        buf_reader.read_exact(&mut hmac_salt)?;

        let mut chacha_salt = [0; 32];
        buf_reader.read_exact(&mut chacha_salt)?;

        let mut ciphertext = Vec::new();
        buf_reader.read_to_end(&mut ciphertext)?;

        Ok(ShifterFile {
            version_number,
            hmac_tag,
            hmac_salt,
            chacha_salt,
            ciphertext,
        })
    }
}
