//! Arithmetic in GF(2^255 - 19) using five 51-bit limbs.
//!
//! Every operation here runs in time independent of its operands: there are no
//! secret-dependent branches, no secret-dependent memory indices, and no
//! variable-latency instructions. Conditional behaviour is expressed as a mask
//! built from a `Choice`.

mod encoding;
mod pow;
#[cfg(test)]
mod tests;

const MASK51: u64 = (1 << 51) - 1;

/// Read eight little-endian bytes starting at `offset`.
#[inline(always)]
const fn load_le64(bytes: &[u8; 32], offset: usize) -> u64 {
    (bytes[offset] as u64)
        | ((bytes[offset + 1] as u64) << 8)
        | ((bytes[offset + 2] as u64) << 16)
        | ((bytes[offset + 3] as u64) << 24)
        | ((bytes[offset + 4] as u64) << 32)
        | ((bytes[offset + 5] as u64) << 40)
        | ((bytes[offset + 6] as u64) << 48)
        | ((bytes[offset + 7] as u64) << 56)
}

/// A field element held as `f0 + f1*2^51 + f2*2^102 + f3*2^153 + f4*2^204`.
///
/// Limbs are kept below `2^52` after every public operation, which leaves room
/// for the lazy reduction the multiplication routines depend on.
#[derive(Clone, Copy, Debug)]
pub struct Fe(pub [u64; 5]);

impl Fe {
    /// The additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0, 0]);
    /// The multiplicative identity.
    pub const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// `sqrt(-1) mod p`, used to take square roots and to decompress points.
    pub const SQRT_M1: Self = Self([
        0x00061b274a0ea0b0,
        0x0000d5a5fc8f189d,
        0x0007ef5e9cbd0c60,
        0x00078595a6804c9e,
        0x0002b8324804fc1d,
    ]);

    /// Sum of two field elements.
    #[inline(always)]
    pub const fn add(&self, rhs: &Self) -> Self {
        let mut out = [0_u64; 5];
        let mut i = 0;
        while i < 5 {
            out[i] = self.0[i] + rhs.0[i];
            i += 1;
        }
        Self(out).weak_reduce()
    }

    /// Difference of two field elements.
    ///
    /// `2 * p` is added limb-wise first so the subtraction never borrows.
    #[inline(always)]
    pub const fn sub(&self, rhs: &Self) -> Self {
        let mut out = [0_u64; 5];
        // 2*p written in 51-bit limbs.
        const P2: [u64; 5] = [
            0x000fffffffffffda,
            0x000ffffffffffffe,
            0x000ffffffffffffe,
            0x000ffffffffffffe,
            0x000ffffffffffffe,
        ];
        let mut i = 0;
        while i < 5 {
            out[i] = self.0[i] + P2[i] - rhs.0[i];
            i += 1;
        }
        Self(out).weak_reduce()
    }

    /// Additive inverse.
    #[inline(always)]
    pub const fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    /// Product of two field elements.
    #[inline(always)]
    pub const fn mul(&self, rhs: &Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = rhs.0;

        // Limbs above the top one fold back in multiplied by 19, because
        // 2^255 = 19 (mod p).
        let b1_19 = (b1 as u128) * 19;
        let b2_19 = (b2 as u128) * 19;
        let b3_19 = (b3 as u128) * 19;
        let b4_19 = (b4 as u128) * 19;

        let (a0, a1, a2, a3, a4) = (a0 as u128, a1 as u128, a2 as u128, a3 as u128, a4 as u128);
        let (b0, b1, b2, b3, b4) = (b0 as u128, b1 as u128, b2 as u128, b3 as u128, b4 as u128);

        let r0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let r1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let r2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let r3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let r4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        Self::carry([r0, r1, r2, r3, r4])
    }

    /// Square of a field element.
    ///
    /// The cross terms are shared, which makes this roughly a third cheaper
    /// than the equivalent `mul`.
    #[inline(always)]
    pub const fn square(&self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let a0_2 = 2 * a0;
        let a1_2 = 2 * a1;
        let a3_19 = 19 * a3;
        let a4_19 = 19 * a4;

        let (a0, a1, a2, a3, a4) = (a0 as u128, a1 as u128, a2 as u128, a3 as u128, a4 as u128);
        let (a0_2, a1_2) = (a0_2 as u128, a1_2 as u128);
        let (a3_19, a4_19) = (a3_19 as u128, a4_19 as u128);

        let r0 = a0 * a0 + a1_2 * a4_19 + 2 * a2 * a3_19;
        let r1 = a0_2 * a1 + 2 * a2 * a4_19 + a3 * a3_19;
        let r2 = a0_2 * a2 + a1 * a1 + 2 * a3 * a4_19;
        let r3 = a0_2 * a3 + a1_2 * a2 + a4 * a4_19;
        let r4 = a0_2 * a4 + a1_2 * a3 + a2 * a2;

        Self::carry([r0, r1, r2, r3, r4])
    }

    /// `self` squared `n` times.
    #[inline(always)]
    pub const fn square_n(&self, n: u32) -> Self {
        let mut out = *self;
        let mut i = 0;
        while i < n {
            out = out.square();
            i += 1;
        }
        out
    }

    /// Multiplication by the Montgomery-ladder constant `a24 = 121666`.
    #[inline(always)]
    pub const fn mul121666(&self) -> Self {
        let mut r = [0_u128; 5];
        let mut i = 0;
        while i < 5 {
            r[i] = (self.0[i] as u128) * 121_666;
            i += 1;
        }
        Self::carry(r)
    }

    /// Reduce five wide accumulators into 51-bit limbs.
    #[inline(always)]
    const fn carry(mut r: [u128; 5]) -> Self {
        let mut out = [0_u64; 5];
        let mut carry = (r[0] >> 51) as u64;
        out[0] = (r[0] as u64) & MASK51;
        r[1] += carry as u128;
        carry = (r[1] >> 51) as u64;
        out[1] = (r[1] as u64) & MASK51;
        r[2] += carry as u128;
        carry = (r[2] >> 51) as u64;
        out[2] = (r[2] as u64) & MASK51;
        r[3] += carry as u128;
        carry = (r[3] >> 51) as u64;
        out[3] = (r[3] as u64) & MASK51;
        r[4] += carry as u128;
        carry = (r[4] >> 51) as u64;
        out[4] = (r[4] as u64) & MASK51;

        // The overflow out of the top limb re-enters at the bottom times 19.
        out[0] += carry * 19;
        out[1] += out[0] >> 51;
        out[0] &= MASK51;
        Self(out)
    }

    /// Propagate carries without a full reduction.
    #[inline(always)]
    const fn weak_reduce(self) -> Self {
        let mut out = self.0;
        let carry = out[4] >> 51;
        out[4] &= MASK51;
        out[0] += carry * 19;
        let mut i = 0;
        while i < 4 {
            out[i + 1] += out[i] >> 51;
            out[i] &= MASK51;
            i += 1;
        }
        Self(out)
    }
}
