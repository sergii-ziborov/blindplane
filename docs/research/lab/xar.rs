use std::arch::aarch64::*;
fn main(){ unsafe{
    let a=0x0123_4567_89ab_cdefu64; let b=0xdead_beef_1234_5678u64;
    let va=vdupq_n_u64(a); let vb=vdupq_n_u64(b);
    for n in [16u64,24,32,63] {
        let got = match n {
            16 => vxarq_u64::<16>(va,vb), 24 => vxarq_u64::<24>(va,vb),
            32 => vxarq_u64::<32>(va,vb), _  => vxarq_u64::<63>(va,vb) };
        let got = core::mem::transmute::<_,[u64;2]>(got)[0];
        let want = (a^b).rotate_right(n as u32);
        println!("XAR #{n:<2} -> {got:016x}  (a^b).rotate_right({n}) = {want:016x}  {}",
                 if got==want {"MATCH"} else {"DIFFER"});
    }
    // EOR3
    let c=0x5555_5555_5555_5555u64;
    let e3 = veor3q_u8(vreinterpretq_u8_u64(va),vreinterpretq_u8_u64(vb),vreinterpretq_u8_u64(vdupq_n_u64(c)));
    let e3 = core::mem::transmute::<_,[u64;2]>(e3)[0];
    println!("EOR3 -> {e3:016x}  a^b^c = {:016x}  {}", a^b^c, if e3==a^b^c {"MATCH"} else {"DIFFER"});
}}
