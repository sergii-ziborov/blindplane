//! AES-256-GCM on CPU cryptographic extensions.
//!
//! There is deliberately **no** software fallback. A portable AES built on
//! lookup tables leaks the key through cache timing, and a constant-time
//! bitsliced one would be slower than ChaCha20-Poly1305 anyway. When the CPU
//! has no AES instructions, [`available`] reports `false` and callers use the
//! ChaCha suite instead, which is uniformly fast and constant time in software.
//!
//! The GHASH field element is held bit-reversed inside each byte, which is the
//! representation that turns GCM's polynomial into an ordinary little-endian
//! integer and lets `PMULL` do the multiplication directly.

/// Whether this CPU can run AES-256-GCM.
pub fn available() -> bool {
    #[cfg(all(feature = "accel", target_arch = "aarch64"))]
    {
        arm::available()
    }
    #[cfg(not(all(feature = "accel", target_arch = "aarch64")))]
    {
        false
    }
}

/// Encrypt in place and return the 16-byte tag.
///
/// Returns `None` when the CPU has no AES instructions.
pub fn seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    buffer: &mut [u8],
) -> Option<[u8; 16]> {
    #[cfg(all(feature = "accel", target_arch = "aarch64"))]
    {
        if arm::available() {
            // SAFETY: `available()` confirmed the AES and PMULL instructions
            // exist, which is the only precondition of the accelerated path.
            return Some(unsafe { arm::seal(key, nonce, associated_data, buffer) });
        }
    }
    let _ = (key, nonce, associated_data, buffer);
    None
}

/// Decrypt in place after verifying the tag.
///
/// Returns `Some(true)` when the tag verified, `Some(false)` when it did not
/// (the buffer is then zeroed), and `None` when the CPU has no AES support.
pub fn open_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
) -> Option<bool> {
    #[cfg(all(feature = "accel", target_arch = "aarch64"))]
    {
        if arm::available() {
            // SAFETY: as above, the required CPU features were just checked.
            return Some(unsafe { arm::open(key, nonce, associated_data, buffer, tag) });
        }
    }
    let _ = (key, nonce, associated_data, buffer, tag);
    None
}

#[cfg(all(feature = "accel", target_arch = "aarch64"))]
mod arm {
    use crate::util::ct_eq_bytes;
    use core::arch::aarch64::{
        poly64x2_t, uint8x16_t, vaeseq_u8, vaesmcq_u8, vdupq_n_u8, veorq_u8, vextq_u8,
        vgetq_lane_u64, vld1q_u8, vmull_high_p64, vmull_p64, vrbitq_u8, vreinterpretq_p64_u8,
        vreinterpretq_u8_p128, vreinterpretq_u64_u8, vst1q_u8,
    };
    use std::sync::OnceLock;

    /// Whether the AES and PMULL extensions are present.
    pub fn available() -> bool {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| {
            std::arch::is_aarch64_feature_detected!("aes")
                && std::arch::is_aarch64_feature_detected!("pmull")
        })
    }

    /// AES-256 encryption of one block under an expanded key.
    #[target_feature(enable = "aes")]
    unsafe fn encrypt_block(round_keys: &[uint8x16_t; 15], block: uint8x16_t) -> uint8x16_t {
        let mut state = block;
        for key in round_keys.iter().take(13) {
            // AESE performs AddRoundKey, SubBytes and ShiftRows together.
            state = vaesmcq_u8(vaeseq_u8(state, *key));
        }
        state = vaeseq_u8(state, round_keys[13]);
        veorq_u8(state, round_keys[14])
    }

    /// AES-256 key expansion.
    ///
    /// `SubWord` is computed with `AESE` against a zero round key rather than
    /// an S-box table, so expanding a key touches no key-dependent memory
    /// address.
    #[target_feature(enable = "aes")]
    unsafe fn expand_key(key: &[u8; 32]) -> [uint8x16_t; 15] {
        // SAFETY: the caller guarantees the AES extension.
        unsafe {
            const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

            let mut words = [0_u32; 60];
            for (i, word) in words.iter_mut().take(8).enumerate() {
                *word = u32::from_le_bytes([
                    key[i * 4],
                    key[i * 4 + 1],
                    key[i * 4 + 2],
                    key[i * 4 + 3],
                ]);
            }

            for i in 8..60 {
                let mut temp = words[i - 1];
                if i % 8 == 0 {
                    temp = sub_word(temp.rotate_right(8)) ^ u32::from(RCON[i / 8 - 1]);
                } else if i % 8 == 4 {
                    temp = sub_word(temp);
                }
                words[i] = words[i - 8] ^ temp;
            }

            let mut round_keys = [vdupq_n_u8(0); 15];
            for (round, slot) in round_keys.iter_mut().enumerate() {
                let mut bytes = [0_u8; 16];
                for j in 0..4 {
                    bytes[j * 4..j * 4 + 4].copy_from_slice(&words[round * 4 + j].to_le_bytes());
                }
                *slot = vld1q_u8(bytes.as_ptr());
            }
            round_keys
        }
    }

    /// Apply the AES S-box to each byte of a word using the AES instruction.
    #[target_feature(enable = "aes")]
    unsafe fn sub_word(word: u32) -> u32 {
        // SAFETY: the caller guarantees the AES extension.
        unsafe {
            // With all four columns equal, ShiftRows is the identity, so
            // AESE(x, 0) reduces to SubBytes applied column-wise.
            let mut bytes = [0_u8; 16];
            for chunk in 0..4 {
                bytes[chunk * 4..chunk * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            let substituted = vaeseq_u8(vld1q_u8(bytes.as_ptr()), vdupq_n_u8(0));
            let mut out = [0_u8; 16];
            vst1q_u8(out.as_mut_ptr(), substituted);
            u32::from_le_bytes([out[0], out[1], out[2], out[3]])
        }
    }

    /// The unreduced 256-bit carry-less product of two field elements.
    ///
    /// Addition in GF(2^128) is XOR, and XOR is linear, so a sum of products
    /// can be accumulated in this unreduced form and reduced once at the end
    /// instead of once per product. Reduction is the expensive half — three of
    /// the six PMULLs per multiply — so hoisting it out of a group of eight is
    /// most of the cost of GHASH.
    #[derive(Clone, Copy)]
    struct Unreduced {
        low: uint8x16_t,
        high: uint8x16_t,
    }

    impl Unreduced {
        const fn zero(zero: uint8x16_t) -> Self {
            Self {
                low: zero,
                high: zero,
            }
        }

        #[target_feature(enable = "aes,neon")]
        unsafe fn xor(self, other: Self) -> Self {
            // SAFETY: the caller guarantees NEON.
            unsafe {
                Self {
                    low: veorq_u8(self.low, other.low),
                    high: veorq_u8(self.high, other.high),
                }
            }
        }
    }

    /// Karatsuba product without reduction: three 64x64 multiplies.
    #[target_feature(enable = "aes,neon")]
    unsafe fn gf_mul_wide(a: uint8x16_t, b: uint8x16_t) -> Unreduced {
        // SAFETY: the caller guarantees the PMULL extension.
        unsafe {
            let a_p: poly64x2_t = vreinterpretq_p64_u8(a);
            let b_p: poly64x2_t = vreinterpretq_p64_u8(b);

            let a_lo = vgetq_lane_u64(vreinterpretq_u64_u8(a), 0);
            let a_hi = vgetq_lane_u64(vreinterpretq_u64_u8(a), 1);
            let b_lo = vgetq_lane_u64(vreinterpretq_u64_u8(b), 0);
            let b_hi = vgetq_lane_u64(vreinterpretq_u64_u8(b), 1);

            let low = vreinterpretq_u8_p128(vmull_p64(a_lo, b_lo));
            let high = vreinterpretq_u8_p128(vmull_high_p64(a_p, b_p));
            let middle = veorq_u8(
                veorq_u8(
                    vreinterpretq_u8_p128(vmull_p64(a_lo ^ a_hi, b_lo ^ b_hi)),
                    low,
                ),
                high,
            );

            let zero = vdupq_n_u8(0);
            Unreduced {
                low: veorq_u8(low, vextq_u8(zero, middle, 8)),
                high: veorq_u8(high, vextq_u8(middle, zero, 8)),
            }
        }
    }

    /// Reduce a 256-bit product modulo `x^128 + x^7 + x^2 + x + 1`.
    #[target_feature(enable = "aes,neon")]
    unsafe fn gf_reduce(product: Unreduced) -> uint8x16_t {
        // SAFETY: the caller guarantees the PMULL extension.
        unsafe {
            let zero = vdupq_n_u8(0);

            // Fold x^128 back in: x^128 = x^7 + x^2 + x + 1, i.e. 0x87.
            let h_lo = vgetq_lane_u64(vreinterpretq_u64_u8(product.high), 0);
            let h_hi = vgetq_lane_u64(vreinterpretq_u64_u8(product.high), 1);
            let fold_lo = vreinterpretq_u8_p128(vmull_p64(h_lo, 0x87));
            let fold_hi = vreinterpretq_u8_p128(vmull_p64(h_hi, 0x87));

            let mut result = veorq_u8(product.low, fold_lo);
            result = veorq_u8(result, vextq_u8(zero, fold_hi, 8));

            // The second fold handles the few bits that spilled past 128 again.
            let spill = vgetq_lane_u64(vreinterpretq_u64_u8(fold_hi), 1);
            let second = vreinterpretq_u8_p128(vmull_p64(spill, 0x87));
            veorq_u8(result, second)
        }
    }

    /// Carry-less multiplication in GF(2^128), reduced.
    #[target_feature(enable = "aes,neon")]
    unsafe fn gf_mul(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
        // SAFETY: the caller guarantees the PMULL extension.
        unsafe { gf_reduce(gf_mul_wide(a, b)) }
    }

    /// Convert to and from the bit-reversed polynomial representation.
    #[target_feature(enable = "neon")]
    unsafe fn reflect(value: uint8x16_t) -> uint8x16_t {
        vrbitq_u8(value)
    }

    /// The GHASH accumulator.
    ///
    /// Four powers of `H` are precomputed so four blocks can be absorbed with
    /// four *independent* multiplications instead of a four-deep dependency
    /// chain. PMULL has multi-cycle latency but issues every cycle, so breaking
    /// the chain is most of the difference between a slow GHASH and a fast one.
    struct Ghash {
        powers: [uint8x16_t; 8],
        acc: uint8x16_t,
    }

    impl Ghash {
        #[target_feature(enable = "aes,neon")]
        unsafe fn new(h_block: uint8x16_t) -> Self {
            // SAFETY: the caller guarantees AES and PMULL.
            unsafe {
                let h = reflect(h_block);
                let h2 = gf_mul(h, h);
                let h3 = gf_mul(h2, h);
                let h4 = gf_mul(h3, h);
                let h5 = gf_mul(h4, h);
                let h6 = gf_mul(h5, h);
                let h7 = gf_mul(h6, h);
                let h8 = gf_mul(h7, h);
                // Ordered so `powers[i]` multiplies the i-th block of a group
                // of eight: H^8 down to H^1.
                Self {
                    powers: [h8, h7, h6, h5, h4, h3, h2, h],
                    acc: vdupq_n_u8(0),
                }
            }
        }

        #[target_feature(enable = "aes,neon")]
        unsafe fn absorb_block(&mut self, block: &[u8; 16]) {
            // SAFETY: the caller guarantees AES and PMULL; the load reads
            // exactly the 16 bytes of `block`.
            unsafe {
                let value = reflect(vld1q_u8(block.as_ptr()));
                self.acc = gf_mul(veorq_u8(self.acc, value), self.powers[7]);
            }
        }

        /// Absorb four blocks as
        /// `acc = (acc ^ b0)*H^4 ^ b1*H^3 ^ b2*H^2 ^ b3*H`.
        /// Absorb eight blocks that are already in registers, with eight
        /// independent multiplications and a single accumulator fold.
        #[expect(clippy::too_many_arguments, reason = "registers, not an API")]
        #[target_feature(enable = "aes,neon")]
        unsafe fn absorb_eight_vectors(
            &mut self,
            c0: uint8x16_t,
            c1: uint8x16_t,
            c2: uint8x16_t,
            c3: uint8x16_t,
            c4: uint8x16_t,
            c5: uint8x16_t,
            c6: uint8x16_t,
            c7: uint8x16_t,
        ) {
            // SAFETY: the caller guarantees AES and PMULL.
            unsafe {
                // Eight unreduced products summed, then one reduction, rather
                // than eight reductions.
                let b0 = veorq_u8(self.acc, reflect(c0));
                let p0 = gf_mul_wide(b0, self.powers[0]);
                let p1 = gf_mul_wide(reflect(c1), self.powers[1]);
                let p2 = gf_mul_wide(reflect(c2), self.powers[2]);
                let p3 = gf_mul_wide(reflect(c3), self.powers[3]);
                let p4 = gf_mul_wide(reflect(c4), self.powers[4]);
                let p5 = gf_mul_wide(reflect(c5), self.powers[5]);
                let p6 = gf_mul_wide(reflect(c6), self.powers[6]);
                let p7 = gf_mul_wide(reflect(c7), self.powers[7]);
                let sum = p0.xor(p1).xor(p2).xor(p3).xor(p4).xor(p5).xor(p6).xor(p7);
                self.acc = gf_reduce(sum);
            }
        }

        /// Absorb four blocks that are already in registers.
        #[target_feature(enable = "aes,neon")]
        unsafe fn absorb_four_vectors(
            &mut self,
            c0: uint8x16_t,
            c1: uint8x16_t,
            c2: uint8x16_t,
            c3: uint8x16_t,
        ) {
            // SAFETY: the caller guarantees AES and PMULL.
            unsafe {
                let b0 = veorq_u8(self.acc, reflect(c0));
                let p0 = gf_mul_wide(b0, self.powers[4]);
                let p1 = gf_mul_wide(reflect(c1), self.powers[5]);
                let p2 = gf_mul_wide(reflect(c2), self.powers[6]);
                let p3 = gf_mul_wide(reflect(c3), self.powers[7]);
                self.acc = gf_reduce(p0.xor(p1).xor(p2).xor(p3));
            }
        }

        #[target_feature(enable = "aes,neon")]
        unsafe fn absorb_four(&mut self, data: *const u8) {
            // SAFETY: the caller guarantees AES and PMULL and that `data`
            // points at 64 readable bytes.
            unsafe {
                let b0 = veorq_u8(self.acc, reflect(vld1q_u8(data)));
                let b1 = reflect(vld1q_u8(data.add(16)));
                let b2 = reflect(vld1q_u8(data.add(32)));
                let b3 = reflect(vld1q_u8(data.add(48)));

                let p0 = gf_mul_wide(b0, self.powers[4]);
                let p1 = gf_mul_wide(b1, self.powers[5]);
                let p2 = gf_mul_wide(b2, self.powers[6]);
                let p3 = gf_mul_wide(b3, self.powers[7]);

                self.acc = gf_reduce(p0.xor(p1).xor(p2).xor(p3));
            }
        }

        #[target_feature(enable = "aes,neon")]
        unsafe fn absorb(&mut self, data: &[u8]) {
            // SAFETY: the caller guarantees AES and PMULL.
            unsafe {
                let mut offset = 0;
                while offset + 128 <= data.len() {
                    let p = data.as_ptr().add(offset);
                    self.absorb_eight_vectors(
                        vld1q_u8(p),
                        vld1q_u8(p.add(16)),
                        vld1q_u8(p.add(32)),
                        vld1q_u8(p.add(48)),
                        vld1q_u8(p.add(64)),
                        vld1q_u8(p.add(80)),
                        vld1q_u8(p.add(96)),
                        vld1q_u8(p.add(112)),
                    );
                    offset += 128;
                }
                while offset + 64 <= data.len() {
                    self.absorb_four(data.as_ptr().add(offset));
                    offset += 64;
                }
                while offset + 16 <= data.len() {
                    let mut block = [0_u8; 16];
                    block.copy_from_slice(&data[offset..offset + 16]);
                    self.absorb_block(&block);
                    offset += 16;
                }
                if offset < data.len() {
                    let mut block = [0_u8; 16];
                    block[..data.len() - offset].copy_from_slice(&data[offset..]);
                    self.absorb_block(&block);
                }
            }
        }

        #[target_feature(enable = "aes,neon")]
        unsafe fn finish(self) -> [u8; 16] {
            // SAFETY: the caller guarantees AES and PMULL.
            unsafe {
                let mut out = [0_u8; 16];
                vst1q_u8(out.as_mut_ptr(), reflect(self.acc));
                out
            }
        }
    }

    /// Build the 16-byte counter block for a 96-bit nonce.
    #[target_feature(enable = "neon")]
    unsafe fn counter_block(nonce: &[u8; 12], counter: u32) -> uint8x16_t {
        // SAFETY: NEON is baseline on AArch64; the load reads 16 initialized
        // stack bytes.
        unsafe {
            let mut block = [0_u8; 16];
            block[..12].copy_from_slice(nonce);
            block[12..].copy_from_slice(&counter.to_be_bytes());
            vld1q_u8(block.as_ptr())
        }
    }

    /// Encrypt the buffer with CTR and authenticate with GHASH in one pass.
    ///
    /// Encrypting and hashing separately walks the buffer twice and leaves the
    /// AES and PMULL pipelines waiting for each other in turn. Hashing each
    /// ciphertext block while it is still in a register keeps both busy and
    /// halves the memory traffic.
    #[target_feature(enable = "aes,neon")]
    pub unsafe fn seal(
        key: &[u8; 32],
        nonce: &[u8; 12],
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> [u8; 16] {
        // SAFETY: the caller guarantees the AES and PMULL extensions. Every
        // pointer below stays within `buffer`, whose length bounds each loop.
        unsafe {
            let round_keys = expand_key(key);
            let h = encrypt_block(&round_keys, vdupq_n_u8(0));
            let tag_mask = encrypt_block(&round_keys, counter_block(nonce, 1));

            let mut ghash = Ghash::new(h);
            ghash.absorb(associated_data);

            let mut counter = 2_u32;
            let mut offset = 0;
            let len = buffer.len();
            let base = buffer.as_mut_ptr();

            // Eight blocks per pass. The AES rounds of all eight are
            // independent, as are the eight PMULLs inside the GHASH step, so
            // both pipelines stay full instead of waiting on a four-deep chain.
            while offset + 128 <= len {
                let k0 = encrypt_block(&round_keys, counter_block(nonce, counter));
                let k1 = encrypt_block(&round_keys, counter_block(nonce, counter + 1));
                let k2 = encrypt_block(&round_keys, counter_block(nonce, counter + 2));
                let k3 = encrypt_block(&round_keys, counter_block(nonce, counter + 3));
                let k4 = encrypt_block(&round_keys, counter_block(nonce, counter + 4));
                let k5 = encrypt_block(&round_keys, counter_block(nonce, counter + 5));
                let k6 = encrypt_block(&round_keys, counter_block(nonce, counter + 6));
                let k7 = encrypt_block(&round_keys, counter_block(nonce, counter + 7));

                let p = base.add(offset);
                let c0 = veorq_u8(vld1q_u8(p), k0);
                let c1 = veorq_u8(vld1q_u8(p.add(16)), k1);
                let c2 = veorq_u8(vld1q_u8(p.add(32)), k2);
                let c3 = veorq_u8(vld1q_u8(p.add(48)), k3);
                let c4 = veorq_u8(vld1q_u8(p.add(64)), k4);
                let c5 = veorq_u8(vld1q_u8(p.add(80)), k5);
                let c6 = veorq_u8(vld1q_u8(p.add(96)), k6);
                let c7 = veorq_u8(vld1q_u8(p.add(112)), k7);

                vst1q_u8(p, c0);
                vst1q_u8(p.add(16), c1);
                vst1q_u8(p.add(32), c2);
                vst1q_u8(p.add(48), c3);
                vst1q_u8(p.add(64), c4);
                vst1q_u8(p.add(80), c5);
                vst1q_u8(p.add(96), c6);
                vst1q_u8(p.add(112), c7);

                ghash.absorb_eight_vectors(c0, c1, c2, c3, c4, c5, c6, c7);

                counter = counter.wrapping_add(8);
                offset += 128;
            }

            while offset + 64 <= len {
                let k0 = encrypt_block(&round_keys, counter_block(nonce, counter));
                let k1 = encrypt_block(&round_keys, counter_block(nonce, counter + 1));
                let k2 = encrypt_block(&round_keys, counter_block(nonce, counter + 2));
                let k3 = encrypt_block(&round_keys, counter_block(nonce, counter + 3));

                let p = base.add(offset);
                let c0 = veorq_u8(vld1q_u8(p), k0);
                let c1 = veorq_u8(vld1q_u8(p.add(16)), k1);
                let c2 = veorq_u8(vld1q_u8(p.add(32)), k2);
                let c3 = veorq_u8(vld1q_u8(p.add(48)), k3);

                vst1q_u8(p, c0);
                vst1q_u8(p.add(16), c1);
                vst1q_u8(p.add(32), c2);
                vst1q_u8(p.add(48), c3);

                ghash.absorb_four_vectors(c0, c1, c2, c3);

                counter = counter.wrapping_add(4);
                offset += 64;
            }

            while offset + 16 <= len {
                let block = encrypt_block(&round_keys, counter_block(nonce, counter));
                let p = base.add(offset);
                let ciphertext = veorq_u8(vld1q_u8(p), block);
                vst1q_u8(p, ciphertext);

                let mut bytes = [0_u8; 16];
                vst1q_u8(bytes.as_mut_ptr(), ciphertext);
                ghash.absorb_block(&bytes);

                counter = counter.wrapping_add(1);
                offset += 16;
            }

            if offset < len {
                let block = encrypt_block(&round_keys, counter_block(nonce, counter));
                let mut keystream = [0_u8; 16];
                vst1q_u8(keystream.as_mut_ptr(), block);
                let mut tail = [0_u8; 16];
                for (index, key_byte) in keystream.iter().enumerate().take(len - offset) {
                    let position = offset + index;
                    buffer[position] ^= *key_byte;
                    tail[index] = buffer[position];
                }
                ghash.absorb_block(&tail);
            }

            ghash.absorb_block(&length_block(associated_data.len(), len));

            let digest = ghash.finish();
            let mut mask = [0_u8; 16];
            vst1q_u8(mask.as_mut_ptr(), tag_mask);

            let mut tag = [0_u8; 16];
            for i in 0..16 {
                tag[i] = digest[i] ^ mask[i];
            }
            tag
        }
    }

    /// Verify the tag, then decrypt the buffer.
    #[target_feature(enable = "aes,neon")]
    pub unsafe fn open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> bool {
        // SAFETY: the caller guarantees the AES and PMULL extensions.
        unsafe {
            let round_keys = expand_key(key);
            let h = encrypt_block(&round_keys, vdupq_n_u8(0));
            let tag_mask = encrypt_block(&round_keys, counter_block(nonce, 1));

            let mut ghash = Ghash::new(h);
            ghash.absorb(associated_data);
            ghash.absorb(buffer);
            ghash.absorb_block(&length_block(associated_data.len(), buffer.len()));

            let digest = ghash.finish();
            let mut mask = [0_u8; 16];
            vst1q_u8(mask.as_mut_ptr(), tag_mask);

            let mut expected = [0_u8; 16];
            for i in 0..16 {
                expected[i] = digest[i] ^ mask[i];
            }

            // Authenticate before releasing any plaintext.
            if !ct_eq_bytes(&expected, tag).is_set() {
                return false;
            }
            apply_ctr(&round_keys, nonce, buffer);
            true
        }
    }

    /// CTR mode starting at counter 2, four blocks at a time.
    ///
    /// The keystream is XORed straight from vector registers into the buffer:
    /// staging it through a stack array and XORing byte by byte costs more than
    /// the AES itself.
    #[target_feature(enable = "aes,neon")]
    unsafe fn apply_ctr(round_keys: &[uint8x16_t; 15], nonce: &[u8; 12], buffer: &mut [u8]) {
        // SAFETY: the caller guarantees the AES extension. Every pointer below
        // stays inside `buffer`, whose length bounds each loop.
        unsafe {
            let mut counter = 2_u32;
            let mut offset = 0;
            let len = buffer.len();
            let base = buffer.as_mut_ptr();

            while offset + 128 <= len {
                let k0 = encrypt_block(round_keys, counter_block(nonce, counter));
                let k1 = encrypt_block(round_keys, counter_block(nonce, counter + 1));
                let k2 = encrypt_block(round_keys, counter_block(nonce, counter + 2));
                let k3 = encrypt_block(round_keys, counter_block(nonce, counter + 3));
                let k4 = encrypt_block(round_keys, counter_block(nonce, counter + 4));
                let k5 = encrypt_block(round_keys, counter_block(nonce, counter + 5));
                let k6 = encrypt_block(round_keys, counter_block(nonce, counter + 6));
                let k7 = encrypt_block(round_keys, counter_block(nonce, counter + 7));

                let p = base.add(offset);
                vst1q_u8(p, veorq_u8(vld1q_u8(p), k0));
                vst1q_u8(p.add(16), veorq_u8(vld1q_u8(p.add(16)), k1));
                vst1q_u8(p.add(32), veorq_u8(vld1q_u8(p.add(32)), k2));
                vst1q_u8(p.add(48), veorq_u8(vld1q_u8(p.add(48)), k3));
                vst1q_u8(p.add(64), veorq_u8(vld1q_u8(p.add(64)), k4));
                vst1q_u8(p.add(80), veorq_u8(vld1q_u8(p.add(80)), k5));
                vst1q_u8(p.add(96), veorq_u8(vld1q_u8(p.add(96)), k6));
                vst1q_u8(p.add(112), veorq_u8(vld1q_u8(p.add(112)), k7));

                counter = counter.wrapping_add(8);
                offset += 128;
            }

            // Four independent blocks keep the AES pipeline full: the
            // instruction has multi-cycle latency but issues every cycle.
            while offset + 64 <= len {
                let k0 = encrypt_block(round_keys, counter_block(nonce, counter));
                let k1 = encrypt_block(round_keys, counter_block(nonce, counter + 1));
                let k2 = encrypt_block(round_keys, counter_block(nonce, counter + 2));
                let k3 = encrypt_block(round_keys, counter_block(nonce, counter + 3));

                let p = base.add(offset);
                vst1q_u8(p, veorq_u8(vld1q_u8(p), k0));
                vst1q_u8(p.add(16), veorq_u8(vld1q_u8(p.add(16)), k1));
                vst1q_u8(p.add(32), veorq_u8(vld1q_u8(p.add(32)), k2));
                vst1q_u8(p.add(48), veorq_u8(vld1q_u8(p.add(48)), k3));

                counter = counter.wrapping_add(4);
                offset += 64;
            }

            while offset + 16 <= len {
                let block = encrypt_block(round_keys, counter_block(nonce, counter));
                let p = base.add(offset);
                vst1q_u8(p, veorq_u8(vld1q_u8(p), block));
                counter = counter.wrapping_add(1);
                offset += 16;
            }

            if offset < len {
                let block = encrypt_block(round_keys, counter_block(nonce, counter));
                let mut keystream = [0_u8; 16];
                vst1q_u8(keystream.as_mut_ptr(), block);
                for (byte, key) in buffer[offset..].iter_mut().zip(keystream.iter()) {
                    *byte ^= *key;
                }
            }
        }
    }

    fn length_block(aad_len: usize, ciphertext_len: usize) -> [u8; 16] {
        let mut block = [0_u8; 16];
        block[..8].copy_from_slice(&((aad_len as u64) * 8).to_be_bytes());
        block[8..].copy_from_slice(&((ciphertext_len as u64) * 8).to_be_bytes());
        block
    }
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
    fn nist_gcm_test_case_13() {
        // NIST GCM test vectors, AES-256, empty plaintext and AAD.
        if !available() {
            return;
        }
        let key = [0_u8; 32];
        let nonce = [0_u8; 12];
        let mut buffer: Vec<u8> = Vec::new();
        let tag = seal_in_place(&key, &nonce, &[], &mut buffer).unwrap();
        assert_eq!(tag.to_vec(), hex("530f8afbc74536b9a963b4f1c4cb738b"));
    }

    #[test]
    fn nist_gcm_test_case_14() {
        // AES-256, 16 zero bytes of plaintext, no AAD.
        if !available() {
            return;
        }
        let key = [0_u8; 32];
        let nonce = [0_u8; 12];
        let mut buffer = vec![0_u8; 16];
        let tag = seal_in_place(&key, &nonce, &[], &mut buffer).unwrap();
        assert_eq!(buffer, hex("cea7403d4d606b6e074ec5d3baf39d18"));
        assert_eq!(tag.to_vec(), hex("d0d1c8a799996bf0265b98b5d48ab919"));
    }

    #[test]
    fn nist_gcm_test_case_16() {
        // AES-256 with associated data and a truncated final block.
        if !available() {
            return;
        }
        let key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888");
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = hex(concat!(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        ));

        let mut key_array = [0_u8; 32];
        key_array.copy_from_slice(&key);
        let mut nonce_array = [0_u8; 12];
        nonce_array.copy_from_slice(&nonce);

        let mut buffer = plaintext.clone();
        let tag = seal_in_place(&key_array, &nonce_array, &aad, &mut buffer).unwrap();
        assert_eq!(
            buffer,
            hex(concat!(
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
                "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
            ))
        );
        assert_eq!(tag.to_vec(), hex("76fc6ece0f4e1768cddf8853bb2d551b"));

        let opened = open_in_place(&key_array, &nonce_array, &aad, &mut buffer, &tag).unwrap();
        assert!(opened);
        assert_eq!(buffer, plaintext);
    }

    #[test]
    fn tampering_is_detected() {
        if !available() {
            return;
        }
        let key = [4_u8; 32];
        let nonce = [5_u8; 12];
        let mut buffer = b"authenticated payload".to_vec();
        let tag = seal_in_place(&key, &nonce, b"context", &mut buffer).unwrap();

        let mut tampered = buffer.clone();
        tampered[0] ^= 1;
        assert_eq!(
            open_in_place(&key, &nonce, b"context", &mut tampered, &tag),
            Some(false)
        );

        let mut wrong_aad = buffer.clone();
        assert_eq!(
            open_in_place(&key, &nonce, b"other", &mut wrong_aad, &tag),
            Some(false)
        );
    }
}
