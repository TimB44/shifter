use std::iter::repeat_n;

/// Implementation of the SHA-256 algorithm.
/// Adopted from https://www.movable-type.co.uk/scripts/sha256.html and
/// https://en.wikipedia.org/wiki/SHA-2.
use super::Key256;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITIAL_HASH_VALUE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub fn sha256(message: &[u8]) -> Key256 {
    let message_length_bits = message.len() * 8;
    let extra_zero_bits = (512 - ((message_length_bits + 1 + 64) & (512 - 1))) & (512 - 1);
    let total_message_len_bits = message_length_bits + 1 + 64 + extra_zero_bits;

    debug_assert_eq!(total_message_len_bits % 512, 0);
    debug_assert_eq!((extra_zero_bits - 7) % 8, 0);
    //Vec::with_capacity(total_message_len_bits / 32);

    let padded_words = message
        .iter()
        .copied()
        //Add a 1 and 7 zeros to the end
        .chain([0x80])
        // Add the rest of the zero padding
        .chain(repeat_n(0, (extra_zero_bits - 7) / 8))
        // add the size in bits as a BE 64 bit integer
        .chain(message_length_bits.to_be_bytes())
        .enumerate()
        .fold::<(Vec<u32>, u32), _>(
            (Vec::with_capacity(total_message_len_bits / 32), 0),
            |(mut words, cur_word), (index, cur_byte)| {
                let new_word = cur_word << 8 | cur_byte as u32;
                if index % 4 == 3 {
                    words.push(new_word)
                }
                (words, new_word)
            },
        )
        .0;

    assert_eq!(padded_words.len() % 16, 0);

    let mut current_hash_value = INITIAL_HASH_VALUE;
    for chunk in padded_words.chunks_exact(16) {
        let mut w = [0; 64];
        w[0..16].copy_from_slice(chunk);
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);

            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = current_hash_value[0];
        let mut b = current_hash_value[1];
        let mut c = current_hash_value[2];
        let mut d = current_hash_value[3];
        let mut e = current_hash_value[4];
        let mut f = current_hash_value[5];
        let mut g = current_hash_value[6];
        let mut h = current_hash_value[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);

            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        current_hash_value[0] = current_hash_value[0].wrapping_add(a);
        current_hash_value[1] = current_hash_value[1].wrapping_add(b);
        current_hash_value[2] = current_hash_value[2].wrapping_add(c);
        current_hash_value[3] = current_hash_value[3].wrapping_add(d);
        current_hash_value[4] = current_hash_value[4].wrapping_add(e);
        current_hash_value[5] = current_hash_value[5].wrapping_add(f);
        current_hash_value[6] = current_hash_value[6].wrapping_add(g);
        current_hash_value[7] = current_hash_value[7].wrapping_add(h);
    }

    return current_hash_value;
}

#[cfg(test)]
mod sha256_tests {

    use super::*;
    use rand::{thread_rng, RngCore};
    use sha2::{Digest, Sha256};

    #[test]
    fn hash_hello_world() {
        assert_eq!(
            sha256(b"Hello World!"),
            [
                0x7f83b165, 0x7ff1fc53, 0xb92dc181, 0x48a1d65d, 0xfc2d4b1f, 0xa3d67728, 0x4addd200,
                0x126d9069
            ]
        )
    }

    #[test]
    fn fuzz() {
        let mut rand = rand::thread_rng();

        let mut buf = [0; 5000];
        for input_len in 0..5000 {
            for _ in 0..50 {
                rand.fill_bytes(&mut buf[0..input_len]);
                let mut hasher = Sha256::new();
                hasher.update(&buf[0..input_len]);
                assert_eq!(
                    hasher.finalize().as_slice(),
                    sha256(&buf[0..input_len])
                        .iter()
                        .map(|w| w.to_be_bytes())
                        .flatten()
                        .collect::<Vec<_>>()
                )
            }
        }
    }
}
