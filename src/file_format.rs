/// This module contains the code the code to create, read and write shifter files  
use std::{
    env::temp_dir,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    string::FromUtf8Error,
};

use rand::{thread_rng, RngCore};
use thiserror::Error;

use crate::crypto::{chacha20, hmac_sha256, pbkdf2, U256};

const SHIFTER_FILE_MAGIC_NUMBER: &[u8; 4] = b"SHFT";
const MIN_SUPPORTED_VERSION_NUMBER: u8 = 1;
const MAX_SUPPORTED_VERSION_NUMBER: u8 = 1;
const MAX_FILENAME_LENGTH: usize = 255;
const CIPHERTEXT_OFFSET: u64 = 101;
const SALT_LEN_BYTES: usize = 32;
const KEY_LEN_BYTES: usize = 32;
const HMAC_TAG_LEN_BYTES: usize = 32;
const FILENAME_FILE_CONTENT_SEPERATOR: u8 = 0;

// nonce is always zero as keys are unique from salt
const CHACHA_NONCE: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

// TODO: Find a good number which balances speed and security
const PBKDF2_ITERATIONS: u32 = 1_000;

pub struct EncryptedShifterFile {
    version_number: u8,
    hmac_tag: U256,
    hmac_key_salt: U256,
    chacha_key_salt: U256,
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

impl EncryptedShifterFile {
    pub fn load_from_file(mut file: File) -> Result<EncryptedShifterFile, ShifterFileParseError> {
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

        let mut hmac_tag = [0; HMAC_TAG_LEN_BYTES];
        file.read_exact(&mut hmac_tag)?;

        let mut hmac_salt = [0; SALT_LEN_BYTES];
        file.read_exact(&mut hmac_salt)?;

        let mut chacha_salt = [0; SALT_LEN_BYTES];
        file.read_exact(&mut chacha_salt)?;

        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext)?;

        Ok(EncryptedShifterFile {
            version_number,
            hmac_tag,
            hmac_key_salt: hmac_salt,
            chacha_key_salt: chacha_salt,
            file,
        })
    }

    fn write_to_file(
        hmac_tag: U256,
        hmac_key_salt: U256,
        chacha_key_salt: U256,
        cipher_text: &[u8],
        mut file: File,
    ) -> Result<Self, io::Error> {
        file.rewind()?;
        file.set_len(0)?;
        file.write_all(SHIFTER_FILE_MAGIC_NUMBER)?;
        file.write_all(&[MAX_SUPPORTED_VERSION_NUMBER])?;
        file.write_all(&hmac_tag)?;
        file.write_all(&hmac_key_salt)?;
        file.write_all(&chacha_key_salt)?;
        file.write_all(cipher_text)?;

        Ok(Self {
            version_number: MAX_SUPPORTED_VERSION_NUMBER,
            hmac_tag,
            hmac_key_salt,
            chacha_key_salt,
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
                let mut buf = [0; KEY_LEN_BYTES];
                pbkdf2(password, &self.hmac_key_salt, PBKDF2_ITERATIONS, &mut buf);
                buf
            },
            || {
                let mut buf = [0; KEY_LEN_BYTES];
                pbkdf2(password, &self.chacha_key_salt, PBKDF2_ITERATIONS, &mut buf);
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

        chacha20(&chacha_dk, &CHACHA_NONCE, &mut ciphertext, 0);
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

    pub fn hmac_tag(&self) -> U256 {
        self.hmac_tag
    }

    pub fn hmac_salt(&self) -> U256 {
        self.hmac_key_salt
    }

    pub fn chacha_salt(&self) -> U256 {
        self.chacha_key_salt
    }
}

impl DecryptedShifterFile {
    pub fn encrypt(
        mut self,
        password: &[u8],
        out: File,
    ) -> Result<EncryptedShifterFile, io::Error> {
        let mut hmac_key_salt = [0; SALT_LEN_BYTES];
        let mut chacha_key_salt = [0; SALT_LEN_BYTES];
        let mut rng = thread_rng();
        rng.fill_bytes(&mut hmac_key_salt);
        rng.fill_bytes(&mut chacha_key_salt);

        let (hmac_dk, chacha_dk) = rayon::join(
            || {
                let mut buf = [0; KEY_LEN_BYTES];
                pbkdf2(password, &hmac_key_salt, PBKDF2_ITERATIONS, &mut buf);
                buf
            },
            || {
                let mut buf = [0; KEY_LEN_BYTES];
                pbkdf2(password, &chacha_key_salt, PBKDF2_ITERATIONS, &mut buf);
                buf
            },
        );

        let mut plaintext = self.filename.as_bytes().to_vec();
        plaintext.push(FILENAME_FILE_CONTENT_SEPERATOR);
        self.contents.rewind()?;
        self.contents.read_to_end(&mut plaintext)?;
        chacha20(&chacha_dk, &CHACHA_NONCE, &mut plaintext, 0);
        let ciphertext = plaintext;
        let hmac_tag = hmac_sha256(&hmac_dk, &ciphertext);

        EncryptedShifterFile::write_to_file(
            hmac_tag,
            hmac_key_salt,
            chacha_key_salt,
            &ciphertext,
            out,
        )
    }
}
