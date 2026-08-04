//! GHASH: the GCM authenticator, on the PMULL carry-less multiply.

use core::arch::aarch64::{
    poly64x2_t, uint8x16_t, vdupq_n_u8, veorq_u8, vextq_u8, vgetq_lane_u64, vld1q_u8,
    vmull_high_p64, vmull_p64, vrbitq_u8, vreinterpretq_p64_u8, vreinterpretq_u8_p128,
    vreinterpretq_u64_u8, vst1q_u8,
};

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
    #[target_feature(enable = "aes,neon")]
    unsafe fn xor(self, other: Self) -> Self {
        Self {
            low: veorq_u8(self.low, other.low),
            high: veorq_u8(self.high, other.high),
        }
    }
}

/// Karatsuba product without reduction: three 64x64 multiplies.
#[target_feature(enable = "aes,neon")]
unsafe fn gf_mul_wide(a: uint8x16_t, b: uint8x16_t) -> Unreduced {
    {
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
    {
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
    // SAFETY: the caller guarantees the PMULL extension, which is the only
    // precondition of both callees.
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
pub(super) struct Ghash {
    powers: [uint8x16_t; 8],
    acc: uint8x16_t,
}

impl Ghash {
    #[target_feature(enable = "aes,neon")]
    pub(super) unsafe fn new(h_block: uint8x16_t) -> Self {
        // SAFETY: the caller guarantees AES and PMULL.
        unsafe {
            // The powers form a tree, not a ladder: after h2 the pairs
            // are independent, so the serial PMULL latency chain is three
            // deep instead of seven.
            let h = reflect(h_block);
            let h2 = gf_mul(h, h);
            let h3 = gf_mul(h2, h);
            let h4 = gf_mul(h2, h2);
            let h5 = gf_mul(h3, h2);
            let h6 = gf_mul(h3, h3);
            let h7 = gf_mul(h4, h3);
            let h8 = gf_mul(h4, h4);
            // Ordered so `powers[i]` multiplies the i-th block of a group
            // of eight: H^8 down to H^1.
            Self {
                powers: [h8, h7, h6, h5, h4, h3, h2, h],
                acc: vdupq_n_u8(0),
            }
        }
    }

    #[target_feature(enable = "aes,neon")]
    pub(super) unsafe fn absorb_block(&mut self, block: &[u8; 16]) {
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
    pub(super) unsafe fn absorb_eight_vectors(
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
    pub(super) unsafe fn absorb_four_vectors(
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
    pub(super) unsafe fn absorb(&mut self, data: &[u8]) {
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
    pub(super) unsafe fn finish(self) -> [u8; 16] {
        // SAFETY: the caller guarantees AES and PMULL.
        unsafe {
            let mut out = [0_u8; 16];
            vst1q_u8(out.as_mut_ptr(), reflect(self.acc));
            out
        }
    }
}
