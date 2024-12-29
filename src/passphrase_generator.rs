use core::str;

const WORD_COUNT: usize = 9_800;
const WORDS_FILE: &[u8; 74376] = include_bytes!("../res/words.txt");
const WORDS: [&'static str; WORD_COUNT] = split_words(WORDS_FILE);

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

#[cfg(test)]
mod passphrase_generator_tests {
    use core::str;

    use super::{WORDS, WORDS_FILE};

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
}
