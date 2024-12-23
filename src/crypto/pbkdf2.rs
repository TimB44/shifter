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

    let rem = blocks.into_remainder();
    debug_assert!(rem.len() == r as usize);
    if !rem.is_empty() {
        rem.copy_from_slice(&generate_block(password, salt, rounds, l)[0..(r as usize)]);
    }
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
    let mut prev = result;

    // We have already ran the first round to skip it
    for _ in 0..(rounds - 1) {
        prev = hmac_sha256(password, &prev);
        slice_xor_assign(&mut result, &prev);
    }

    result
}

// Test vectors adapted from https://www.rfc-editor.org/rfc/rfc7914.txt#[cfg(test)]
#[cfg(test)]
mod pbkdf2_tests {
    use std::time::Instant;

    use rand::{thread_rng, Rng, RngCore};
    use sha2::Sha256;

    use crate::crypto::{
        pbkdf2::pbkdf2,
        sha256::{sha256, sha_256_64_bytes},
    };
    use pbkdf2::pbkdf2_hmac;

    #[test]
    fn test_vector_one_iteration() {
        let p = b"passwd";
        let s = b"salt";
        let c = 1;
        let mut output = [0; 64];

        let expected_output = [
            0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44,
            0xb6, 0x05, 0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57,
            0xc2, 0x0d, 0xac, 0xbc, 0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45, 0x99, 0x16,
            0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31, 0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5,
            0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83,
        ];

        pbkdf2(p, s, c, &mut output);

        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_vector_many_iterations() {
        let p = b"Password";
        let s = b"NaCl";
        let c = 80_000;
        let mut output = [0; 64];

        let expected_output = [
            0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21, 0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27,
            0x01, 0xf9, 0x64, 0x1a, 0x44, 0x18, 0xd0, 0x4c, 0x04, 0x14, 0xae, 0xff, 0x08, 0x87,
            0x6b, 0x34, 0xab, 0x56, 0xa1, 0xd4, 0x25, 0xa1, 0x22, 0x58, 0x33, 0x54, 0x9a, 0xdb,
            0x84, 0x1b, 0x51, 0xc9, 0xb3, 0x17, 0x6a, 0x27, 0x2b, 0xde, 0xbb, 0xa1, 0xd0, 0x78,
            0x47, 0x8f, 0x62, 0xb3, 0x97, 0xf3, 0x3c, 0x8d,
        ];

        pbkdf2(p, s, c, &mut output);

        assert_eq!(output, expected_output);
    }

    use rayon::prelude::*;
    #[test]
    fn differential_fuzz() {
        (0..3).into_par_iter().for_each(|iter| {
            let mut rng = thread_rng();
            let mut p = vec![0; rng.gen_range(0..50_000)];
            rng.fill_bytes(&mut p);

            let mut s = vec![0; rng.gen_range(0..50_000)];
            rng.fill_bytes(&mut s);

            let rounds = rng.gen_range(1..10_000);

            let dk_len = rng.gen_range(1..1024);
            let mut out1 = vec![0; dk_len];
            let mut out2 = vec![0; dk_len];

            let before = Instant::now();
            pbkdf2_hmac::<Sha256>(&p, &s, rounds, &mut out1);
            eprintln!(
                "iter = {iter} time 1 = {:?}",
                Instant::now().duration_since(before)
            );

            let before = Instant::now();
            pbkdf2(&p, &s, rounds, &mut out2);
            eprintln!(
                "iter = {iter} time 2 = {:?}",
                Instant::now().duration_since(before)
            );
            assert_eq!(out1, out2);
        });
    }
}
