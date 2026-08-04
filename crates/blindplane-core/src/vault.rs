//! Payload suite selection and vault key derivation.

use blindplane_crypto::aead::Suite;
use blindplane_crypto::argon2::{Argon2Params, argon2id};
use blindplane_crypto::util::Secret;

use crate::error::CryptoError;

/// The fastest payload suite this CPU supports.
///
/// HPKE envelope wrapping stays on the fixed RFC 9180 ChaCha suite for wire
/// interoperability; this choice only affects bulk payload encryption.
pub fn fastest_payload_suite() -> Suite {
    Suite::fastest_available()
}

/// Derive a client vault key from a password.
///
/// The password never leaves the client and the derived key never reaches the
/// server. The cost parameters are the defence: see [`Argon2Params`].
pub fn derive_vault_key(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Secret<32>, CryptoError> {
    let derived =
        argon2id(password, salt, params).map_err(|_| CryptoError::InvalidVaultParameters)?;
    if derived.len() != 32 {
        return Err(CryptoError::InvalidVaultParameters);
    }
    let mut key = Secret::zeroed();
    key.as_mut().copy_from_slice(&derived);
    Ok(key)
}
