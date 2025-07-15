use core::str;

use rand::Rng;

const WORD_COUNT: usize = 9_800;
const WORDS: [&str; WORD_COUNT] = split_words(include_bytes!("../res/words.txt"));
const PASSPHRASE_GENERATOR_DELIMTER: &str = "-";
pub const DEFAULT_PASSPHRASE_LENGTH: usize = 8;
pub const MIN_PASSPHRASE_LENGTH: usize = 1;
pub const MAX_PASSPHRASE_LENGTH: usize = 1000;

const fn split_words(mut input: &[u8]) -> [&str; WORD_COUNT] {
    let mut words: [&str; WORD_COUNT] = [""; WORD_COUNT];
    let mut cur_word = 0;

    while cur_word < WORD_COUNT {
        let mut cur_byte = 0;
        while input[cur_byte] != b'\n' {
            cur_byte += 1;
        }

        let (word, left_over) = input.split_at(cur_byte);

        //TODO: Remove the unsafe if more const is added
        // Saftey: Test words_valid_utf8 ensures that words are valid utf8 and ascii. This unsafe block is
        // used as unwrap is not yet a const fn
        words[cur_word] = unsafe { std::str::from_utf8_unchecked(word) };
        cur_word += 1;

        // Remove the '\n' byte
        input = left_over.split_at(1).1;
    }
    words
}

/// Generates a random passphrase with length number of words joined by a hypen
pub fn generate_passphrase(length: Option<usize>) -> String {
    let length = length.unwrap_or(DEFAULT_PASSPHRASE_LENGTH);
    assert!(length >= MIN_PASSPHRASE_LENGTH && length <= MAX_PASSPHRASE_LENGTH);
    let mut rand = rand::thread_rng();
    (0..length)
        .flat_map(|cur| {
            if cur == length - 1 {
                [WORDS[rand.gen_range(0..WORD_COUNT)], ""]
            } else {
                [
                    WORDS[rand.gen_range(0..WORD_COUNT)],
                    PASSPHRASE_GENERATOR_DELIMTER,
                ]
            }
        })
        .collect()
}

#[cfg(test)]
mod passphrase_generator_tests {
    use core::str;

    use super::{generate_passphrase, PASSPHRASE_GENERATOR_DELIMTER, WORDS};
    const WORDS_FILE: &[u8; 74376] = include_bytes!("../res/words.txt");

    #[test]
    fn words_valid_utf8() {
        let all_words = str::from_utf8(WORDS_FILE).unwrap();
        assert!(all_words.is_ascii());
    }

    #[test]
    fn words_split_correctly() {
        let all_words = str::from_utf8(WORDS_FILE).unwrap();
        let words: Vec<_> = all_words.lines().collect();

        assert_eq!(&WORDS, words.as_slice());
    }

    #[test]
    #[should_panic]
    fn zero_length_empty() {
        generate_passphrase(Some(0));
    }

    #[test]
    fn fuzz() {
        for length in 1..800 {
            let pf = generate_passphrase(Some(length));

            // should have exactly length - 1 hyphens
            assert_eq!(
                pf.chars()
                    .filter(|&x| x == PASSPHRASE_GENERATOR_DELIMTER.chars().next().unwrap())
                    .count(),
                length - 1
            );

            // generated passphrase should not have any white space
            assert!(!pf.contains(|c: char| c.is_whitespace()));
        }
    }
}
