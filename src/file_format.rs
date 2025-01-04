/// This module contains the code to create, read and write shifter files  
use std::{
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

#[derive(Debug)]
pub struct EncryptedShifterFile {
    version_number: u8,
    hmac_tag: U256,
    hmac_key_salt: U256,
    chacha_key_salt: U256,
    file: File,
}

#[derive(Debug)]
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

    #[error("original filename length {:?} outside of valid range [1, {MAX_FILENAME_LENGTH}]", filename.len())]
    InvalidFileNameLength {
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

    // TODO: possibly remove this and inlcude it in invalid length
    #[error("plaintext missing null byte seperator between filename and content")]
    NoNullByte { file_contents: File },
}

impl EncryptedShifterFile {
    pub fn load_from_file(mut file: File) -> Result<EncryptedShifterFile, ShifterFileParseError> {
        file.rewind()?;
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
        mut out: File,
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

        let mut ciphertext = self.chiphertext()?;
        let tag = hmac_sha256(&hmac_dk, &mut ciphertext);
        if self.hmac_tag != tag {
            return Err(ShifterFileDecryptError::HmacTagIncorrect {
                expected_tag: self.hmac_tag,
                calcuated_tag: tag,
            });
        }

        chacha20(&chacha_dk, &CHACHA_NONCE, &mut ciphertext, 0);
        let plaintext = ciphertext;

        out.rewind()?;
        out.set_len(0)?;

        // The first null byte is the seperator between the filename and filecontents
        let split = match plaintext.iter().position(|&b| b == 0) {
            Some(p) => p,
            None => {
                out.write_all(&plaintext)?;
                return Err(ShifterFileDecryptError::NoNullByte { file_contents: out });
            }
        };

        out.write_all(&plaintext[(split + 1)..])?;

        let filename = match String::from_utf8(plaintext[0..split].to_vec()) {
            Ok(filename) => filename,
            Err(err) => {
                return Err(ShifterFileDecryptError::InvalidFilenameUtf8 {
                    err,
                    file_contents: out,
                })
            }
        };

        if split < 1 || split > MAX_FILENAME_LENGTH {
            return Err(ShifterFileDecryptError::InvalidFileNameLength {
                filename,
                file_contents: out,
            });
        }

        return Ok(DecryptedShifterFile {
            filename,
            contents: out,
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

    pub fn chiphertext(&mut self) -> Result<Vec<u8>, io::Error> {
        let mut out = Vec::new();
        self.file.seek(SeekFrom::Start(CIPHERTEXT_OFFSET))?;
        self.file.read_to_end(&mut out)?;
        Ok(out)
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

#[cfg(test)]
mod file_format_tests {
    use std::{
        env::temp_dir,
        fs::{self, remove_file, File},
        io::{Read, Seek, Write},
        path::PathBuf,
    };

    use rand::{distributions::Alphanumeric, thread_rng, Rng, RngCore};

    use crate::file_format::ShifterFileParseError;

    use super::{DecryptedShifterFile, EncryptedShifterFile, CIPHERTEXT_OFFSET};
    const GENERIC_ENCRYPTED_FILE_HEADER: [u8; CIPHERTEXT_OFFSET as usize] = [
        83, 72, 70, 84, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
        44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66,
        67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
        90, 91, 92, 93, 94, 95, 96,
    ];

    fn generate_random_tempfile_path() -> PathBuf {
        temp_dir()
            .join(rand::thread_rng().next_u64().to_string())
            .with_extension(".shifted")
    }

    #[test]
    fn load_from_file_incorrect_magic_number() {
        let mut data = GENERIC_ENCRYPTED_FILE_HEADER.to_vec();
        let incorrect_magic_number = b"SHFF".clone();
        data[0..4].copy_from_slice(&incorrect_magic_number);
        data.extend_from_slice(b"THIS IS THE BODY");

        let path = generate_random_tempfile_path();
        let mut file = File::create_new(path.clone()).unwrap();
        file.write_all(&data).unwrap();
        fs::write(path.clone(), &data.clone()).unwrap();

        assert!(match EncryptedShifterFile::load_from_file(file) {
            Err(ShifterFileParseError::IncorrectMagicNumber {
                actual_magic_number: mn,
            }) if mn == incorrect_magic_number => true,
            _ => false,
        });
        remove_file(path).unwrap();
    }

    #[test]
    fn load_from_file_too_short() {
        let mut data = GENERIC_ENCRYPTED_FILE_HEADER.to_vec();
        data.truncate(30);

        let path = generate_random_tempfile_path();
        let mut file = File::create_new(path.clone()).unwrap();
        file.write_all(&data).unwrap();

        assert!(matches!(
            EncryptedShifterFile::load_from_file(file),
            Err(ShifterFileParseError::ReadError(_))
        ));
        remove_file(path).unwrap();
    }

    #[test]
    fn load_from_file_wrong_version_number() {
        for version in [0, 2, 255] {
            let mut data = GENERIC_ENCRYPTED_FILE_HEADER.to_vec();
            data.extend_from_slice(b"THIS IS THE BODY");
            data[4] = version;

            let path = generate_random_tempfile_path();
            let mut file = File::create_new(path.clone()).unwrap();
            file.write_all(&data).unwrap();

            assert!(match EncryptedShifterFile::load_from_file(file) {
                Err(ShifterFileParseError::IncorrectVersionNumber { actual_verion: v })
                    if v == version =>
                    true,
                _ => false,
            });
            remove_file(path).unwrap();
        }
    }

    #[test]
    fn load_from_file_correct() {
        let mut data = GENERIC_ENCRYPTED_FILE_HEADER.to_vec();
        data.extend_from_slice(b"THIS IS THE BODY");

        let path = generate_random_tempfile_path();
        let mut file = File::create_new(path.clone()).unwrap();
        file.write_all(&data).unwrap();

        let mut result = EncryptedShifterFile::load_from_file(file).unwrap();

        assert_eq!(result.version_number, 1);
        assert_eq!(&(result.hmac_tag), (1..=32).collect::<Vec<u8>>().as_slice());
        assert_eq!(
            &(result.hmac_key_salt),
            (33..=64).collect::<Vec<u8>>().as_slice()
        );
        assert_eq!(
            &(result.chacha_key_salt),
            (65..=96).collect::<Vec<u8>>().as_slice()
        );
        assert_eq!(result.chiphertext().unwrap(), b"THIS IS THE BODY");
        remove_file(path).unwrap();
    }

    #[test]
    fn load_from_file_empty_body_works() {
        let data = GENERIC_ENCRYPTED_FILE_HEADER.to_vec();

        let path = generate_random_tempfile_path();
        let mut file = File::create_new(path.clone()).unwrap();
        file.write_all(&data).unwrap();

        let mut result = EncryptedShifterFile::load_from_file(file).unwrap();

        assert_eq!(result.version_number, 1);
        assert_eq!(&(result.hmac_tag), (1..=32).collect::<Vec<u8>>().as_slice());
        assert_eq!(
            &(result.hmac_key_salt),
            (33..=64).collect::<Vec<u8>>().as_slice()
        );
        assert_eq!(
            &(result.chacha_key_salt),
            (65..=96).collect::<Vec<u8>>().as_slice()
        );
        assert_eq!(result.chiphertext().unwrap(), b"");
        remove_file(path).unwrap();
    }

    #[test]
    fn load_from_file_random() {
        let mut rand = thread_rng();
        for _ in 0..100 {
            let mut data = GENERIC_ENCRYPTED_FILE_HEADER.to_vec();
            let mut hmac_tag = [0; 32];
            let mut hmac_key_salt = [0; 32];
            let mut chacha_key_salt = [0; 32];
            rand.fill_bytes(&mut hmac_tag);
            rand.fill_bytes(&mut hmac_key_salt);
            rand.fill_bytes(&mut chacha_key_salt);
            data[5..37].copy_from_slice(&hmac_tag);
            data[37..69].copy_from_slice(&hmac_key_salt);
            data[69..101].copy_from_slice(&chacha_key_salt);
            let body_len = rand.gen_range(0..500_000);
            let mut body = vec![0; body_len];

            rand.fill_bytes(&mut body);
            data.extend_from_slice(&body);

            let file_name = generate_random_tempfile_path();
            let mut file = File::create_new(file_name.clone()).unwrap();
            file.write_all(&data).unwrap();

            let mut result = EncryptedShifterFile::load_from_file(file).unwrap();

            assert_eq!(result.version_number, 1);
            assert_eq!(result.hmac_tag, hmac_tag);
            assert_eq!(result.hmac_key_salt, hmac_key_salt);
            assert_eq!(result.chacha_key_salt, chacha_key_salt);
            assert_eq!(result.chiphertext().unwrap(), body);
            remove_file(file_name).unwrap();
        }
    }

    use rayon::prelude::*;
    #[test]
    fn encrypt_decrpyt_file_fuzz() {
        (0..500).into_par_iter().for_each(|_| {
            let mut rand = thread_rng();
            let body_len = rand.gen_range(0..100_000);
            let mut data = vec![0; body_len];
            rand.fill_bytes(&mut data);
            let data = data;
            let contents_name = generate_random_tempfile_path();
            let mut contents = File::create_new(&contents_name).unwrap();
            contents.write_all(&data).unwrap();

            let password_len = rand.gen_range(0..2_000);
            let mut password = vec![0; password_len];
            rand.fill_bytes(&mut password);
            let filename: String = rand
                .clone()
                .sample_iter(&Alphanumeric)
                .take(rand.gen_range(1..256))
                .map(|c| c as char)
                .collect();

            let out_name = generate_random_tempfile_path();
            let out = File::create_new(&out_name).unwrap();

            let dsf = DecryptedShifterFile {
                filename: filename.clone(),
                contents,
            };

            let decrypted_name = generate_random_tempfile_path();
            let decrypted = File::create_new(&decrypted_name).unwrap();
            let mut esf = dsf.encrypt(&password, out).unwrap();
            let mut result = esf.decrypt(&password, decrypted).unwrap();
            assert_eq!(result.filename, filename);
            result.contents.rewind().unwrap();

            let mut data_after = Vec::new();
            result.contents.read_to_end(&mut data_after).unwrap();
            assert_eq!(data_after, data);

            // Clean up files from test
            remove_file(contents_name).unwrap();
            remove_file(out_name).unwrap();
            remove_file(decrypted_name).unwrap();
        });
    }
}
