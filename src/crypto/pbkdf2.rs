use crate::crypto::{hmac::hmac_sha256, utils::slice_xor_assign};

/// Reference from https://www.ietf.org/rfc/rfc2898.txt

const H_LEN: u32 = crate::crypto::sha256::SHA_256_OUTPUT_SIZE_BITS / 8;
pub fn pbkdf2(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    assert!(rounds > 0);
    let dk_len: u32 = out.len().try_into().expect("derived key too long");
    let l = dk_len.div_ceil(H_LEN);
    let r = dk_len % H_LEN;
    let mut blocks = out.chunks_exact_mut(H_LEN as usize);

    let mut block_num = 1;
    while let Some(block) = blocks.next() {
        block.copy_from_slice(&generate_block(password, salt, rounds, block_num as u32));
        block_num += 1;
    }

    blocks
        .into_remainder()
        .copy_from_slice(&generate_block(password, salt, rounds, l)[0..(r as usize)]);
}

fn generate_block(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    block_num: u32,
) -> [u8; H_LEN as usize] {
    let initial_message: Vec<_> = salt
        .iter()
        .copied()
        .chain(block_num.to_be_bytes())
        .collect();

    let mut result = hmac_sha256(password, &initial_message);

    // We have already ran the first round to skip it
    for _ in 0..(rounds - 1) {
        let next = hmac_sha256(password, &result);
        slice_xor_assign(&mut result, &next);
    }

    result
}
