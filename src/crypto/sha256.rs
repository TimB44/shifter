use std::iter::repeat_n;

/// Implementation of the SHA-256 algorithm.
/// Adopted from https://www.movable-type.co.uk/scripts/sha256.html and
/// https://en.wikipedia.org/wiki/SHA-2.
use super::U256;

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

pub const SHA_256_BLOCK_SIZE_BITS: u32 = 512;
pub const SHA_256_OUTPUT_SIZE_BITS: u32 = 256;

pub const SHA_256_BLOCK_SIZE_BYTES: u32 = SHA_256_BLOCK_SIZE_BITS / 8;
pub const SHA_256_OUTPUT_SIZE_BYTES: u32 = SHA_256_OUTPUT_SIZE_BITS / 8;

pub fn sha256(message: &[u8]) -> U256 {
    let message_length_bits = message.len() * 8;
    let extra_zero_bits = (512 - ((message_length_bits + 1 + 64) & (512 - 1))) & (512 - 1);
    let total_message_len_bits = message_length_bits + 1 + 64 + extra_zero_bits;

    debug_assert_eq!(total_message_len_bits % 512, 0);
    debug_assert_eq!((extra_zero_bits - 7) % 8, 0);
    //Vec::with_capacity(total_message_len_bits / 32);

    let mut iter = message
        .iter()
        .copied()
        //Add a 1 and 7 zeros to the end
        .chain([0x80])
        // Add the rest of the zero padding
        .chain(repeat_n(0, (extra_zero_bits - 7) / 8))
        // add the size in bits as a BE 64 bit integer
        .chain((message_length_bits as u64).to_be_bytes());

    let mut padded_words = vec![0; total_message_len_bits / 32];
    for location in padded_words.iter_mut() {
        *location = u32::from_be_bytes([
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
        ])
    }

    assert_eq!(padded_words.len() % 16, 0);

    let mut current_hash = INITIAL_HASH_VALUE;
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
        let mut a = current_hash[0];
        let mut b = current_hash[1];
        let mut c = current_hash[2];
        let mut d = current_hash[3];
        let mut e = current_hash[4];
        let mut f = current_hash[5];
        let mut g = current_hash[6];
        let mut h = current_hash[7];

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

        current_hash[0] = current_hash[0].wrapping_add(a);
        current_hash[1] = current_hash[1].wrapping_add(b);
        current_hash[2] = current_hash[2].wrapping_add(c);
        current_hash[3] = current_hash[3].wrapping_add(d);
        current_hash[4] = current_hash[4].wrapping_add(e);
        current_hash[5] = current_hash[5].wrapping_add(f);
        current_hash[6] = current_hash[6].wrapping_add(g);
        current_hash[7] = current_hash[7].wrapping_add(h);
    }

    let mut final_hash = [0; 32];
    for (i, &word) in current_hash.iter().enumerate() {
        final_hash[(i * 4)..(i * 4 + 4)].copy_from_slice(&word.to_be_bytes());
    }

    final_hash
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    #[test]
    fn hash_hello_world() {
        assert_eq!(
            sha256(b"Hello World!"),
            [
                0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53, 0xb9, 0x2d, 0xc1, 0x81, 0x48, 0xa1,
                0xd6, 0x5d, 0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28, 0x4a, 0xdd, 0xd2, 0x00,
                0x12, 0x6d, 0x90, 0x69
            ]
        )
    }

    #[test]
    fn hash_empty_string() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        )
    }

    #[test]
    fn fuzz() {
        let mut rand = rand::thread_rng();

        let mut buf = [0; 5000];
        for input_len in 0..5000 {
            rand.fill_bytes(&mut buf[0..input_len]);
            let mut hasher = Sha256::new();
            hasher.update(&buf[0..input_len]);
            assert_eq!(hasher.finalize().as_slice(), sha256(&buf[0..input_len]))
        }
    }
}
