use crate::crypto::utils::slice_xor_assign;

use super::Key256;

const CHA_CHA_WORD_SIZE: usize = 4;
const CHA_CHA_STATE_WORD_SIZE: usize = 16;
const CHA_CHA_STATE_BYTE_SIZE: usize = CHA_CHA_STATE_WORD_SIZE * 4;
const CHA_CHA_ROUND_COUNT: u32 = 20;
const CHA_CHA_CONSTANTS: [u8; 16] = *b"expand 32-byte k";
const COUNTER_WORD: usize = 12;

type ChaChaBlock = [u32; CHA_CHA_STATE_WORD_SIZE];
pub fn chacha20(key: &[u8; 32], nonce: &[u8; 12], text: &mut [u8], initial_counter: u32) {
    let state = generate_common_block(key, nonce);
    let mut iter = text.chunks_exact_mut(CHA_CHA_STATE_BYTE_SIZE);

    let mut block_counter = initial_counter;
    while let Some(block) = iter.next() {
        slice_xor_assign(
            block,
            &serialize_state(&gernerate_block(state, block_counter)),
        );
        block_counter += 1;
    }

    let remainder = iter.into_remainder();
    if !remainder.is_empty() {
        slice_xor_assign(
            remainder,
            &(serialize_state(&gernerate_block(state, block_counter)))[0..(remainder.len())],
        );
    }
}

fn gernerate_block(mut src_block: ChaChaBlock, block_num: u32) -> ChaChaBlock {
    src_block[COUNTER_WORD] = block_num;
    let mut result = src_block;
    run_rounds(&mut result);

    for (a, b) in result.iter_mut().zip(src_block) {
        *a = a.wrapping_add(b);
    }

    result
}

fn run_rounds(block: &mut ChaChaBlock) {
    // Each iteration of the loop does 2 iterations
    for _ in 0..(CHA_CHA_ROUND_COUNT / 2) {
        // column rounds
        quarter_round(0, 4, 8, 12, block);
        quarter_round(1, 5, 9, 13, block);
        quarter_round(2, 6, 10, 14, block);
        quarter_round(3, 7, 11, 15, block);

        // diagonal rounds
        quarter_round(0, 5, 10, 15, block);
        quarter_round(1, 6, 11, 12, block);
        quarter_round(2, 7, 8, 13, block);
        quarter_round(3, 4, 9, 14, block);
    }
}

fn serialize_state(state: &ChaChaBlock) -> [u8; CHA_CHA_STATE_BYTE_SIZE] {
    let mut result = [0; CHA_CHA_STATE_BYTE_SIZE];
    for (word_b, word) in result.chunks_exact_mut(4).zip(state) {
        word_b.copy_from_slice(&word.to_le_bytes());
    }

    result
}

fn quarter_round(a: usize, b: usize, c: usize, d: usize, internal_state: &mut ChaChaBlock) {
    internal_state[a] = internal_state[a].wrapping_add(internal_state[b]);
    internal_state[d] ^= internal_state[a];
    internal_state[d] = internal_state[d].rotate_left(16);

    internal_state[c] = internal_state[c].wrapping_add(internal_state[d]);
    internal_state[b] ^= internal_state[c];
    internal_state[b] = internal_state[b].rotate_left(12);

    internal_state[a] = internal_state[a].wrapping_add(internal_state[b]);
    internal_state[d] ^= internal_state[a];
    internal_state[d] = internal_state[d].rotate_left(8);

    internal_state[c] = internal_state[c].wrapping_add(internal_state[d]);
    internal_state[b] ^= internal_state[c];
    internal_state[b] = internal_state[b].rotate_left(7);
}

fn generate_common_block(key: &[u8; 32], nonce: &[u8; 12]) -> ChaChaBlock {
    [
        // First row contains the ChaCha constants
        u32::from_le_bytes([
            CHA_CHA_CONSTANTS[0],
            CHA_CHA_CONSTANTS[1],
            CHA_CHA_CONSTANTS[2],
            CHA_CHA_CONSTANTS[3],
        ]),
        u32::from_le_bytes([
            CHA_CHA_CONSTANTS[4],
            CHA_CHA_CONSTANTS[5],
            CHA_CHA_CONSTANTS[6],
            CHA_CHA_CONSTANTS[7],
        ]),
        u32::from_le_bytes([
            CHA_CHA_CONSTANTS[8],
            CHA_CHA_CONSTANTS[9],
            CHA_CHA_CONSTANTS[10],
            CHA_CHA_CONSTANTS[11],
        ]),
        u32::from_le_bytes([
            CHA_CHA_CONSTANTS[12],
            CHA_CHA_CONSTANTS[13],
            CHA_CHA_CONSTANTS[14],
            CHA_CHA_CONSTANTS[15],
        ]),
        // Second row contians the first half of the ky
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        // Thirt row contains the second half of the key
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        // last row continas the block counter left as (zero for now) and the nonce
        0,
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ]
}

// Test vectors from https://datatracker.ietf.org/doc/rfc7539/
#[cfg(test)]
mod chacha20_tests {

    use crate::crypto::chacha20::chacha20;

    use super::quarter_round;

    #[test]
    fn quarter_round_test_vector() {
        let mut test_state = [
            0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        quarter_round(0, 1, 2, 3, &mut test_state);

        assert_eq!(
            test_state,
            [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        )
    }

    #[test]
    fn chacha_test_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let initial_counter = 1;

        let mut plaintext = [
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e,
            0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
            0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
            0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72,
            0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ];

        let ciphertext = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];

        chacha20(&key, &nonce, &mut plaintext, initial_counter);
        assert_eq!(plaintext, ciphertext)
    }

    // TODO Add fuzz tests using existing chacha crate
}
