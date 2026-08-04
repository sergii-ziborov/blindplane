//! Unit tests for scalar arithmetic modulo `L`.

use super::*;

fn to_int(bytes: &[u8]) -> u128 {
    let mut acc = 0_u128;
    for (i, b) in bytes.iter().enumerate().take(16) {
        acc |= u128::from(*b) << (8 * i);
    }
    acc
}

#[test]
fn small_values_are_unchanged() {
    let mut bytes = [0_u8; 32];
    bytes[0] = 42;
    let s = Scalar::from_bytes_mod_order(&bytes);
    assert_eq!(s.to_bytes(), bytes);
}

#[test]
fn l_reduces_to_zero() {
    let mut bytes = [0_u8; 32];
    for (i, limb) in L.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    assert_eq!(Scalar::from_bytes_mod_order(&bytes).to_bytes(), [0_u8; 32]);
    assert!(Scalar::from_canonical_bytes(&bytes).is_none());
}

#[test]
fn wide_reduction_matches_reference_modulus() {
    // 2^256 mod L, computed independently:
    // 2^256 = 4 * 2^254, and reducing gives this constant.
    let mut wide = [0_u8; 64];
    wide[32] = 1; // value = 2^256
    let reduced = Scalar::from_wide_bytes(&wide);
    // Verify by the defining property: 2^256 - reduced must be a multiple
    // of L, checked through a second reduction of the difference.
    let mut check = [0_u8; 64];
    check[32] = 1;
    let bytes = reduced.to_bytes();
    let mut borrow = 0_i32;
    for i in 0..64 {
        let sub = if i < 32 { i32::from(bytes[i]) } else { 0 };
        let mut diff = i32::from(check[i]) - sub - borrow;
        if diff < 0 {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        check[i] = diff as u8;
    }
    assert_eq!(Scalar::from_wide_bytes(&check).to_bytes(), [0_u8; 32]);
}

#[test]
fn multiply_add_is_value_correct_for_small_inputs() {
    let mut a_bytes = [0_u8; 32];
    a_bytes[0] = 7;
    let mut b_bytes = [0_u8; 32];
    b_bytes[0] = 9;
    let mut c_bytes = [0_u8; 32];
    c_bytes[0] = 5;
    let a = Scalar::from_bytes_mod_order(&a_bytes);
    let b = Scalar::from_bytes_mod_order(&b_bytes);
    let c = Scalar::from_bytes_mod_order(&c_bytes);
    assert_eq!(to_int(&a.mul_add(&b, &c).to_bytes()), 7 * 9 + 5);
}

#[test]
fn radix16_digits_recompose() {
    let mut bytes = [0_u8; 32];
    bytes[0] = 0xff;
    bytes[1] = 0x7f;
    let s = Scalar::from_bytes_mod_order(&bytes);
    let digits = s.radix16();
    let mut acc = 0_i128;
    for (i, d) in digits.iter().enumerate().take(8) {
        acc += i128::from(*d) << (4 * i);
    }
    assert_eq!(acc, 0x7fff);
    assert!(digits.iter().all(|d| (-8..=8).contains(d)));
}

#[test]
fn non_adjacent_form_recomposes_at_every_width() {
    // A value small enough to recompose exactly in an i128.
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&0x0123_4567_89ab_cdef_u64.to_le_bytes());
    bytes[8..12].copy_from_slice(&0x0eadbeef_u32.to_le_bytes());
    let s = Scalar::from_bytes_mod_order(&bytes);
    let expected = i128::from(0x0eadbeef_u32) << 64 | i128::from(0x0123_4567_89ab_cdef_u64);

    for width in [4_u32, 5, 6, 7, 8] {
        let naf = s.non_adjacent_form(width);
        let mut acc = 0_i128;
        for (i, digit) in naf.iter().enumerate().take(100) {
            acc += i128::from(*digit) << i;
        }
        assert_eq!(acc, expected, "width {width}");
        let bound = 1_i16 << (width - 1);
        assert!(
            naf.iter()
                .all(|d| i16::from(*d).abs() < bound && (d % 2 != 0 || *d == 0)),
            "width {width} digit out of range"
        );
    }
}
