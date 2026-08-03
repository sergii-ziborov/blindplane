//! HMAC and HKDF over SHA-256 and SHA-512.

use crate::sha2::{Sha256, Sha512};
use crate::util::{Choice, ct_eq_bytes, secure_erase};

/// HMAC-SHA-256 (RFC 2104).
pub struct HmacSha256 {
    inner: Sha256,
    outer_key: [u8; 64],
}

impl HmacSha256 {
    /// Output length in bytes.
    pub const OUTPUT_LEN: usize = 32;

    /// Start a MAC under `key`, which may be any length.
    pub fn new(key: &[u8]) -> Self {
        let mut block = [0_u8; 64];
        if key.len() > 64 {
            block[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }

        let mut inner_key = [0_u8; 64];
        let mut outer_key = [0_u8; 64];
        for i in 0..64 {
            inner_key[i] = block[i] ^ 0x36;
            outer_key[i] = block[i] ^ 0x5c;
        }
        secure_erase(&mut block);

        let mut inner = Sha256::new();
        inner.update(&inner_key);
        secure_erase(&mut inner_key);

        Self { inner, outer_key }
    }

    /// Absorb more message bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finish and return the tag.
    pub fn finalize(mut self) -> [u8; 32] {
        let inner = std::mem::take(&mut self.inner).finalize();
        let mut outer = Sha256::new();
        outer.update(&self.outer_key);
        outer.update(&inner);
        outer.finalize()
    }

    /// Finish and compare against an expected tag in constant time.
    pub fn verify(self, expected: &[u8]) -> Choice {
        ct_eq_bytes(&self.finalize(), expected)
    }

    /// One-shot MAC.
    pub fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac = Self::new(key);
        mac.update(data);
        mac.finalize()
    }
}

impl Drop for HmacSha256 {
    fn drop(&mut self) {
        secure_erase(&mut self.outer_key);
    }
}

/// HMAC-SHA-512.
pub struct HmacSha512 {
    inner: Sha512,
    outer_key: [u8; 128],
}

impl HmacSha512 {
    /// Output length in bytes.
    pub const OUTPUT_LEN: usize = 64;

    /// Start a MAC under `key`, which may be any length.
    pub fn new(key: &[u8]) -> Self {
        let mut block = [0_u8; 128];
        if key.len() > 128 {
            block[..64].copy_from_slice(&Sha512::digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }

        let mut inner_key = [0_u8; 128];
        let mut outer_key = [0_u8; 128];
        for i in 0..128 {
            inner_key[i] = block[i] ^ 0x36;
            outer_key[i] = block[i] ^ 0x5c;
        }
        secure_erase(&mut block);

        let mut inner = Sha512::new();
        inner.update(&inner_key);
        secure_erase(&mut inner_key);

        Self { inner, outer_key }
    }

    /// Absorb more message bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finish and return the tag.
    pub fn finalize(mut self) -> [u8; 64] {
        let inner = std::mem::take(&mut self.inner).finalize();
        let mut outer = Sha512::new();
        outer.update(&self.outer_key);
        outer.update(&inner);
        outer.finalize()
    }

    /// One-shot MAC.
    pub fn mac(key: &[u8], data: &[u8]) -> [u8; 64] {
        let mut mac = Self::new(key);
        mac.update(data);
        mac.finalize()
    }
}

impl Drop for HmacSha512 {
    fn drop(&mut self) {
        secure_erase(&mut self.outer_key);
    }
}

/// HKDF-SHA-256 extract (RFC 5869).
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    HmacSha256::mac(salt, ikm)
}

/// HKDF-SHA-256 expand (RFC 5869).
///
/// Returns `false` and leaves `okm` untouched when more than 255 blocks are
/// requested, which is outside the construction's security argument.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], okm: &mut [u8]) -> bool {
    if okm.len() > 255 * 32 {
        return false;
    }
    let mut previous = [0_u8; 32];
    let mut previous_len = 0;
    let mut counter = 1_u8;
    let mut written = 0;

    while written < okm.len() {
        let mut mac = HmacSha256::new(prk);
        mac.update(&previous[..previous_len]);
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finalize();
        previous_len = 32;

        let take = core::cmp::min(32, okm.len() - written);
        okm[written..written + take].copy_from_slice(&previous[..take]);
        written += take;
        counter = counter.wrapping_add(1);
    }
    secure_erase(&mut previous);
    true
}

/// HKDF-SHA-256 in one call.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> bool {
    let mut prk = hkdf_extract(salt, ikm);
    let ok = hkdf_expand(&prk, info, okm);
    secure_erase(&mut prk);
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc4231_hmac_sha256_case_1() {
        let key = [0x0b_u8; 20];
        assert_eq!(
            HmacSha256::mac(&key, b"Hi There").to_vec(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }

    #[test]
    fn rfc4231_hmac_sha256_case_2() {
        assert_eq!(
            HmacSha256::mac(b"Jefe", b"what do ya want for nothing?").to_vec(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn rfc4231_hmac_sha256_long_key() {
        let key = [0xaa_u8; 131];
        assert_eq!(
            HmacSha256::mac(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )
            .to_vec(),
            hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    #[test]
    fn rfc4231_hmac_sha512_case_2() {
        assert_eq!(
            HmacSha512::mac(b"Jefe", b"what do ya want for nothing?").to_vec(),
            hex(concat!(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            ))
        );
    }

    #[test]
    fn rfc5869_hkdf_case_1() {
        let ikm = [0x0b_u8; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            prk.to_vec(),
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );

        let mut okm = [0_u8; 42];
        assert!(hkdf_expand(&prk, &info, &mut okm));
        assert_eq!(
            okm.to_vec(),
            hex(concat!(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                "34007208d5b887185865"
            ))
        );
    }

    #[test]
    fn rfc5869_hkdf_case_3_empty_salt_and_info() {
        let ikm = [0x0b_u8; 22];
        let prk = hkdf_extract(&[], &ikm);
        assert_eq!(
            prk.to_vec(),
            hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
        );

        let mut okm = [0_u8; 42];
        assert!(hkdf_expand(&prk, &[], &mut okm));
        assert_eq!(
            okm.to_vec(),
            hex(concat!(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
                "9d201395faa4b61a96c8"
            ))
        );
    }

    #[test]
    fn expand_rejects_oversized_output() {
        let prk = [0_u8; 32];
        let mut okm = vec![0_u8; 255 * 32 + 1];
        assert!(!hkdf_expand(&prk, b"info", &mut okm));
    }
}
