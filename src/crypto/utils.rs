pub fn slice_xor_assign(lhs: &mut [u8], rhs: &[u8]) {
    debug_assert!(lhs.len() == rhs.len());
    for (old, new) in lhs.iter_mut().zip(rhs) {
        *old ^= new;
    }
}
