//! Unit tests for field element arithmetic.

use super::*;
use crate::util::Choice;

fn from_u64(v: u64) -> Fe {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&v.to_le_bytes());
    Fe::from_bytes(&bytes)
}

#[test]
fn add_sub_round_trip() {
    let a = from_u64(0x1234_5678_9abc_def0);
    let b = from_u64(0x0fed_cba9_8765_4321);
    assert_eq!(a.add(&b).sub(&b).to_bytes(), a.to_bytes());
}

#[test]
fn multiplication_matches_square() {
    let a = from_u64(0xdead_beef_cafe_1234);
    assert_eq!(a.mul(&a).to_bytes(), a.square().to_bytes());
}

#[test]
fn inverse_is_an_inverse() {
    let a = from_u64(9);
    assert_eq!(a.mul(&a.invert()).to_bytes(), Fe::ONE.to_bytes());
}

#[test]
fn canonical_encoding_reduces_p_to_zero() {
    // p itself must encode as zero.
    let mut p_bytes = [0xff_u8; 32];
    p_bytes[0] = 0xed;
    p_bytes[31] = 0x7f;
    assert_eq!(Fe::from_bytes(&p_bytes).to_bytes(), [0_u8; 32]);
}

#[test]
fn sqrt_m1_squares_to_minus_one() {
    assert_eq!(
        Fe::SQRT_M1.square().to_bytes(),
        Fe::ONE.neg().to_bytes(),
        "sqrt(-1)^2 must be -1"
    );
}

#[test]
fn selection_is_value_correct() {
    let a = from_u64(7);
    let b = from_u64(9);
    assert_eq!(
        Fe::select(&a, &b, Choice::from_bit(0)).to_bytes(),
        a.to_bytes()
    );
    assert_eq!(
        Fe::select(&a, &b, Choice::from_bit(1)).to_bytes(),
        b.to_bytes()
    );
}
