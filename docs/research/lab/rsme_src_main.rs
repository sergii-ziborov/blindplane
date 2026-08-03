use std::arch::asm;
use std::time::Instant;

/// Detect SME at runtime via sysctl (no third-party deps).
fn has_sme() -> bool {
    unsafe {
        let name = b"hw.optional.arm.FEAT_SME\0";
        let mut val: i32 = 0;
        let mut len: usize = 4;
        extern "C" { fn sysctlbyname(n:*const u8,o:*mut i32,s:*mut usize,nw:*const u8,nl:usize)->i32; }
        sysctlbyname(name.as_ptr(), &mut val, &mut len, std::ptr::null(), 0) == 0 && val == 1
    }
}

/// ChaCha20-shaped add/xor-rotate on 512-bit streaming SVE vectors.
/// Entire streaming region is one asm block: no compiler code may run inside.
#[inline(never)]
unsafe fn sve_chacha_rounds(iters: u64) {
    asm!(
        ".arch armv9-a+sme+sme2+sme-i16i64",
        "smstart sm",
        "2:",
        "add z0.s,z0.s,z1.s", "xar z3.s,z3.s,z0.s,#16",
        "add z2.s,z2.s,z3.s", "xar z1.s,z1.s,z2.s,#20",
        "add z0.s,z0.s,z1.s", "xar z3.s,z3.s,z0.s,#24",
        "add z2.s,z2.s,z3.s", "xar z1.s,z1.s,z2.s,#25",
        "add z4.s,z4.s,z5.s", "xar z7.s,z7.s,z4.s,#16",
        "add z6.s,z6.s,z7.s", "xar z5.s,z5.s,z6.s,#20",
        "add z4.s,z4.s,z5.s", "xar z7.s,z7.s,z4.s,#24",
        "add z6.s,z6.s,z7.s", "xar z5.s,z5.s,z6.s,#25",
        "add z8.s,z8.s,z9.s", "xar z11.s,z11.s,z8.s,#16",
        "add z10.s,z10.s,z11.s", "xar z9.s,z9.s,z10.s,#20",
        "add z8.s,z8.s,z9.s", "xar z11.s,z11.s,z8.s,#24",
        "add z10.s,z10.s,z11.s", "xar z9.s,z9.s,z10.s,#25",
        "add z12.s,z12.s,z13.s", "xar z15.s,z15.s,z12.s,#16",
        "add z14.s,z14.s,z15.s", "xar z13.s,z13.s,z14.s,#20",
        "add z12.s,z12.s,z13.s", "xar z15.s,z15.s,z12.s,#24",
        "add z14.s,z14.s,z15.s", "xar z13.s,z13.s,z14.s,#25",
        "subs {n}, {n}, #1",
        "b.ne 2b",
        "smstop sm",
        n = inout(reg) iters => _,
        // smstart/smstop zero the vector file: v8-v15 are callee-saved, must be clobbered
        out("v8") _, out("v9") _, out("v10") _, out("v11") _,
        out("v12") _, out("v13") _, out("v14") _, out("v15") _,
        out("v0") _, out("v1") _, out("v2") _, out("v3") _,
        out("v4") _, out("v5") _, out("v6") _, out("v7") _,
        options(nostack)
    );
}

/// SMOPA i16->i64 outer product, correctness check.
#[inline(never)]
unsafe fn smopa_i16(a: &[i16;32], b: &[i16;32], out: &mut [i64;64]) {
    asm!(
        ".arch armv9-a+sme+sme2+sme-i16i64",
        "smstart",
        "ptrue p0.h", "ptrue p1.d",
        "ld1h {{z0.h}}, p0/z, [{a}]",
        "ld1h {{z1.h}}, p0/z, [{b}]",
        "zero {{za}}",
        "smopa za0.d, p0/m, p0/m, z0.h, z1.h",
        "mov {t}, {o}",
        "mov w12, #0",
        "3:",
        "st1d {{za0h.d[w12,0]}}, p1, [{t}]",
        "add {t}, {t}, #64",
        "add w12, w12, #1",
        "cmp w12, #8",
        "b.lt 3b",
        "smstop",
        a = in(reg) a.as_ptr(), b = in(reg) b.as_ptr(), o = in(reg) out.as_mut_ptr(),
        t = out(reg) _,
        out("v0") _, out("v1") _, out("v8") _, out("v9") _, out("v10") _,
        out("v11") _, out("v12") _, out("v13") _, out("v14") _, out("v15") _,
        out("x12") _,
        options(nostack)
    );
}

fn main() {
    println!("SME available: {}", has_sme());
    if !has_sme() { return; }

    // correctness: one-hot a[3]=1, b[7]=1 -> 4-way dot, k=3 aligns
    let mut a=[0i16;32]; let mut b=[0i16;32]; a[3]=1; b[7]=1;
    let mut out=[0i64;64];
    unsafe { smopa_i16(&a,&b,&mut out) };
    let nz: Vec<(usize,i64)> = out.iter().enumerate().filter(|(_,&v)| v!=0).map(|(i,&v)|(i,v)).collect();
    println!("SMOPA i16->i64 one-hot nonzeros: {:?}", nz);

    // dense check vs reference 4-way dot
    for i in 0..32 { a[i]=(i as i16)+1; b[i]=2*(i as i16)+1; }
    unsafe { smopa_i16(&a,&b,&mut out) };
    let mut r1=[0i64;64]; let mut r2=[0i64;64];
    for r in 0..8 { for c in 0..8 { let (mut s1,mut s2)=(0i64,0i64);
        for k in 0..4 { s1 += (a[4*c+k] as i64)*(b[4*r+k] as i64);
                        s2 += (a[4*r+k] as i64)*(b[4*c+k] as i64); }
        r1[8*r+c]=s1; r2[8*r+c]=s2; }}
    println!("SMOPA dense == sum_k a[4c+k]*b[4r+k] : {}", out==r1);
    println!("SMOPA dense == sum_k a[4r+k]*b[4c+k] : {}", out==r2);

    // throughput
    let it=5_000_000u64;
    unsafe { sve_chacha_rounds(1000) };
    let t=Instant::now(); unsafe { sve_chacha_rounds(it) }; let d=t.elapsed();
    // 2 chains x 2 QR-pairs = 4 QRs per iter, 16 u32 lanes each
    let lane_qr = 8.0*16.0*(it as f64);
    let gbs = lane_qr/80.0*64.0/ d.as_secs_f64() /1e9;
    println!("Rust streaming-SVE ChaCha20 core: {:.2} GB/s (single thread)", gbs);
}
