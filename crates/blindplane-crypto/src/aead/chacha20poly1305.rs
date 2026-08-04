//! The fused ChaCha20-Poly1305 seal and open, and the XChaCha20 subkey split.

use crate::chacha::{ChaCha20, hchacha20};
use crate::poly1305::Poly1305;
use crate::util::{Secret, secure_erase};

use super::TAG_LEN;

/// Derive the XChaCha subkey and the 96-bit nonce it is used with.
pub(super) fn xchacha_split(key: &[u8; 32], nonce: &[u8]) -> (Secret<32>, [u8; 12]) {
    let mut hchacha_nonce = [0_u8; 16];
    hchacha_nonce.copy_from_slice(&nonce[..16]);
    let subkey = hchacha20(key, &hchacha_nonce);

    let mut inner = [0_u8; 12];
    inner[4..].copy_from_slice(&nonce[16..24]);
    (Secret::new(subkey), inner)
}

/// Bytes sealed per step of the fused encrypt-and-MAC loop.
///
/// 512 is one pass of the cipher's eight-block fast path. The cipher runs on
/// the vector pipes and Poly1305 on the scalar multiplier, so once a chunk is
/// encrypted its MAC costs overlap with encrypting the next chunk; the
/// out-of-order window does the interleaving that fused assembly does by hand.
const FUSE_CHUNK: usize = 512;

pub(super) fn chacha20poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    buffer: &mut [u8],
) -> [u8; TAG_LEN] {
    let mut mac = Poly1305::new(&poly_key(key, nonce));
    mac.update(associated_data);
    mac.pad_to_block();

    let mut cipher = ChaCha20::new(key, nonce, 1);
    for chunk in buffer.chunks_mut(FUSE_CHUNK) {
        cipher.apply_keystream(chunk);
        mac.update(chunk);
    }

    mac.pad_to_block();
    mac.update(&(associated_data.len() as u64).to_le_bytes());
    mac.update(&(buffer.len() as u64).to_le_bytes());
    mac.finalize()
}

pub(super) fn chacha20poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> bool {
    let mut mac = Poly1305::new(&poly_key(key, nonce));
    mac.update(associated_data);
    mac.pad_to_block();
    mac.update(buffer);
    mac.pad_to_block();
    mac.update(&(associated_data.len() as u64).to_le_bytes());
    mac.update(&(buffer.len() as u64).to_le_bytes());

    if !mac.verify(tag).is_set() {
        return false;
    }
    ChaCha20::new(key, nonce, 1).apply_keystream(buffer);
    true
}

/// The one-time Poly1305 key is the cipher's block zero.
fn poly_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    ChaCha20::new(key, nonce, 0).apply_keystream(&mut block);
    let mut poly_key = [0_u8; 32];
    poly_key.copy_from_slice(&block[..32]);
    secure_erase(&mut block);
    poly_key
}
