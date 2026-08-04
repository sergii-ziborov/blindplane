//! AES-256-GCM on the ARMv8 AES and PMULL instructions.

mod ghash;
mod key_schedule;
mod seal_open;

pub use seal_open::{open, seal};

use std::sync::OnceLock;

/// Whether the AES and PMULL extensions are present.
pub fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
    })
}
