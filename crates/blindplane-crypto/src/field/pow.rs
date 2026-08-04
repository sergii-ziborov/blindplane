//! The two fixed addition-chain exponentiations: inversion and the
//! square-root exponent.

use super::Fe;

impl Fe {
    /// Multiplicative inverse, computed as `self^(p-2)`.
    ///
    /// The addition chain is the standard 254-step ladder: 11 multiplications
    /// and 254 squarings, all unconditional.
    pub const fn invert(&self) -> Self {
        let z1 = *self;
        let z2 = z1.square();
        let z8 = z2.square_n(2);
        let z9 = z1.mul(&z8);
        let z11 = z2.mul(&z9);
        let z22 = z11.square();
        let z_5_0 = z9.mul(&z22);
        let z_10_5 = z_5_0.square_n(5);
        let z_10_0 = z_10_5.mul(&z_5_0);
        let z_20_10 = z_10_0.square_n(10);
        let z_20_0 = z_20_10.mul(&z_10_0);
        let z_40_20 = z_20_0.square_n(20);
        let z_40_0 = z_40_20.mul(&z_20_0);
        let z_50_10 = z_40_0.square_n(10);
        let z_50_0 = z_50_10.mul(&z_10_0);
        let z_100_50 = z_50_0.square_n(50);
        let z_100_0 = z_100_50.mul(&z_50_0);
        let z_200_100 = z_100_0.square_n(100);
        let z_200_0 = z_200_100.mul(&z_100_0);
        let z_250_50 = z_200_0.square_n(50);
        let z_250_0 = z_250_50.mul(&z_50_0);
        let z_255_5 = z_250_0.square_n(5);
        z_255_5.mul(&z11)
    }

    /// `self^((p-5)/8)`, the exponent used when taking square roots.
    pub const fn pow_p58(&self) -> Self {
        let z1 = *self;
        let z2 = z1.square();
        let z8 = z2.square_n(2);
        let z9 = z1.mul(&z8);
        let z11 = z2.mul(&z9);
        let z22 = z11.square();
        let z_5_0 = z9.mul(&z22);
        let z_10_5 = z_5_0.square_n(5);
        let z_10_0 = z_10_5.mul(&z_5_0);
        let z_20_10 = z_10_0.square_n(10);
        let z_20_0 = z_20_10.mul(&z_10_0);
        let z_40_20 = z_20_0.square_n(20);
        let z_40_0 = z_40_20.mul(&z_20_0);
        let z_50_10 = z_40_0.square_n(10);
        let z_50_0 = z_50_10.mul(&z_10_0);
        let z_100_50 = z_50_0.square_n(50);
        let z_100_0 = z_100_50.mul(&z_50_0);
        let z_200_100 = z_100_0.square_n(100);
        let z_200_0 = z_200_100.mul(&z_100_0);
        let z_250_50 = z_200_0.square_n(50);
        let z_250_0 = z_250_50.mul(&z_50_0);
        let z_252_2 = z_250_0.square_n(2);
        z_252_2.mul(&z1)
    }
}
