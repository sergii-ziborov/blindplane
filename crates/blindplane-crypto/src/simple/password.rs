//! Password hashing and verification.

use crate::argon2::{Argon2Params, argon2id};
use crate::rand;
use crate::util::ct_eq_bytes;

use super::{CryptoError, HASH_LEN, SALT_LEN};

/// Hash a password for storage.
///
/// The returned string carries the salt and the parameters, so it is the only
/// thing to store. Hand it back to [`verify_password`] at login. This is not
/// encryption and cannot be reversed, which is the point.
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let mut salt = [0_u8; SALT_LEN];
    rand::fill(&mut salt).map_err(|_| CryptoError::Randomness)?;

    let params = Argon2Params::default();
    let hash = argon2id(password.as_bytes(), &salt, params)?;

    // Self-describing, so the cost parameters can be raised later without
    // invalidating hashes already stored.
    Ok(format!(
        "argon2id$v=19$m={},t={},p=1${}${}",
        params.memory_kib,
        params.passes,
        hex(&salt),
        hex(&hash)
    ))
}

/// Check a password against a stored hash from [`hash_password`].
///
/// Returns `false` for a wrong password and for a malformed stored value; it
/// never panics on bad input, because that input often comes from a database
/// somebody else can write to.
#[must_use]
pub fn verify_password(password: &str, stored: &str) -> bool {
    let Some((salt, expected, params)) = parse_stored(stored) else {
        return false;
    };
    let Ok(derived) = argon2id(password.as_bytes(), &salt, params) else {
        return false;
    };
    ct_eq_bytes(&derived, &expected).is_set()
}

fn parse_stored(stored: &str) -> Option<(Vec<u8>, Vec<u8>, Argon2Params)> {
    let mut parts = stored.split('$');
    if parts.next()? != "argon2id" || parts.next()? != "v=19" {
        return None;
    }

    let mut memory_kib = 0_u32;
    let mut passes = 0_u32;
    for setting in parts.next()?.split(',') {
        let (name, value) = setting.split_once('=')?;
        match name {
            "m" => memory_kib = value.parse().ok()?,
            "t" => passes = value.parse().ok()?,
            "p" => {
                if value != "1" {
                    return None;
                }
            }
            _ => return None,
        }
    }

    let salt = unhex(parts.next()?)?;
    let expected = unhex(parts.next()?)?;
    if parts.next().is_some() || salt.len() < 8 || expected.is_empty() {
        return None;
    }

    Some((
        salt,
        expected,
        Argon2Params {
            memory_kib,
            passes,
            output_len: HASH_LEN,
        },
    ))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 15)] as char);
    }
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.is_empty() {
        return None;
    }
    let bytes = text.as_bytes();
    (0..bytes.len() / 2)
        .map(|i| {
            let hi = (bytes[i * 2] as char).to_digit(16)?;
            let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
            Some(((hi << 4) | lo) as u8)
        })
        .collect()
}
