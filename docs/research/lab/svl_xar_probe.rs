use std::arch::asm;

/// Confirm SVL (streaming vector length) and that XAR does what we think.
/// XAR is XOR-then-rotate-RIGHT by an immediate. A ChaCha left-rotate by n on
/// 32-bit lanes should therefore be xar #(32-n).
fn main() {
    unsafe {
        // 1. Read SVL in bytes via rdsvl.
        let svl: u64;
        asm!(
            ".arch armv9-a+sme+sme2",
            "smstart sm",
            "rdsvl {n}, #1",
            "smstop sm",
            n = out(reg) svl,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            options(nostack)
        );
        println!("SVL = {} bytes = {} u32 lanes", svl, svl / 4);

        // 2. XAR semantics: load two known vectors, xar them, store, compare
        //    against the scalar model (a ^ b) rotate_right(imm).
        let a_in = [0x1234_5678u32; 16];
        let b_in = [0x9abc_def0u32; 16];
        let mut out_buf = [0u32; 16];
        asm!(
            ".arch armv9-a+sme+sme2",
            "smstart sm",
            "ptrue p0.s",
            "ld1w {{z0.s}}, p0/z, [{a}]",
            "ld1w {{z1.s}}, p0/z, [{b}]",
            // xar zd.s, zd.s, zm.s, #imm  -> zd = ror(zd ^ zm, imm)
            "xar z0.s, z0.s, z1.s, #16",
            "st1w {{z0.s}}, p0, [{o}]",
            "smstop sm",
            a = in(reg) a_in.as_ptr(),
            b = in(reg) b_in.as_ptr(),
            o = in(reg) out_buf.as_mut_ptr(),
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("p0") _,
            options(nostack)
        );
        let expect_ror16 = (a_in[0] ^ b_in[0]).rotate_right(16);
        let expect_rol16 = (a_in[0] ^ b_in[0]).rotate_left(16);
        println!("xar #16 -> {:08x}", out_buf[0]);
        println!("  ror16 = {:08x} {}", expect_ror16, if out_buf[0]==expect_ror16 {"<-- MATCH"} else {""});
        println!("  rol16 = {:08x} {}", expect_rol16, if out_buf[0]==expect_rol16 {"<-- MATCH"} else {""});
        println!("all 16 lanes equal: {}", out_buf.iter().all(|&x| x == out_buf[0]));

        // 3. Verify rotate-left-by-12 maps to xar #20.
        let mut out12 = [0u32; 16];
        asm!(
            ".arch armv9-a+sme+sme2",
            "smstart sm",
            "ptrue p0.s",
            "ld1w {{z0.s}}, p0/z, [{a}]",
            "ld1w {{z1.s}}, p0/z, [{b}]",
            "xar z0.s, z0.s, z1.s, #20",
            "st1w {{z0.s}}, p0, [{o}]",
            "smstop sm",
            a = in(reg) a_in.as_ptr(),
            b = in(reg) b_in.as_ptr(),
            o = in(reg) out12.as_mut_ptr(),
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("p0") _,
            options(nostack)
        );
        println!("xar #20 == rotl12: {}", out12[0] == (a_in[0]^b_in[0]).rotate_left(12));
    }
}
