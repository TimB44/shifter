use core::str;

use rand::Rng;

const WORD_COUNT: usize = 9_800;
const WORDS: [&'static str; WORD_COUNT] = split_words(include_bytes!("../res/words.txt"));
const PASSPHRASE_GENERATOR_DELIMTER: &str = "-";

const fn split_words(mut input: &[u8]) -> [&str; WORD_COUNT] {
    let mut words: [&str; WORD_COUNT] = [""; WORD_COUNT];
    let mut cur_word = 0;

    while cur_word < WORD_COUNT {
        let mut cur_byte = 0;
        while input[cur_byte] != '\n' as u8 {
            cur_byte += 1;
        }

        let (word, left_over) = input.split_at(cur_byte);

        words[cur_word] = unsafe { std::str::from_utf8_unchecked(word) };
        cur_word += 1;

        // Remove the '\n' byte
        input = left_over.split_at(1).1;
    }
    words
}

/// Generates a random passphrase with length number of words joined by a hypen
pub fn generate_passphrase(length: usize) -> String {
    let mut rand = rand::thread_rng();
    (0..length)
        .into_iter()
        .map(|cur| {
            if cur == length - 1 {
                [WORDS[rand.gen_range(0..WORD_COUNT)], ""]
            } else {
                [
                    WORDS[rand.gen_range(0..WORD_COUNT)],
                    PASSPHRASE_GENERATOR_DELIMTER,
                ]
            }
        })
        .flatten()
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
    fn fuzz() {
        for length in 1..800 {
            let pf = generate_passphrase(length);

            // should have eactlye length - 1 hyphens
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
