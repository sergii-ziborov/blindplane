// Plain scalar RFC 8439 ChaCha20 reference. No SIMD, no cleverness.
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
fn qr(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = v[a].wrapping_add(v[b]); v[d] = (v[d] ^ v[a]).rotate_left(16);
    v[c] = v[c].wrapping_add(v[d]); v[b] = (v[b] ^ v[c]).rotate_left(12);
    v[a] = v[a].wrapping_add(v[b]); v[d] = (v[d] ^ v[a]).rotate_left(8);
    v[c] = v[c].wrapping_add(v[d]); v[b] = (v[b] ^ v[c]).rotate_left(7);
}
fn block(key: &[u8;32], nonce: &[u8;12], counter: u32) -> [u8;64] {
    let mut s = [0u32;16];
    s[..4].copy_from_slice(&SIGMA);
    for i in 0..8 { s[4+i] = u32::from_le_bytes(key[i*4..i*4+4].try_into().unwrap()); }
    s[12] = counter;
    for i in 0..3 { s[13+i] = u32::from_le_bytes(nonce[i*4..i*4+4].try_into().unwrap()); }
    let init = s;
    for _ in 0..10 {
        qr(&mut s,0,4,8,12); qr(&mut s,1,5,9,13); qr(&mut s,2,6,10,14); qr(&mut s,3,7,11,15);
        qr(&mut s,0,5,10,15); qr(&mut s,1,6,11,12); qr(&mut s,2,7,8,13); qr(&mut s,3,4,9,14);
    }
    let mut out = [0u8;64];
    for i in 0..16 { out[i*4..i*4+4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes()); }
    out
}
fn main() {
    // RFC 8439 section 2.4.2 sanity check.
    let key: [u8;32] = core::array::from_fn(|i| i as u8);
    let mut nonce = [0u8;12]; nonce[4..].copy_from_slice(&[0,0,0,0x4a,0,0,0,0]);
    let b = block(&key, &nonce, 1);
    assert_eq!(&b[..4], &[0x22,0x4f,0x51,0xf3]);
    eprintln!("[ok] scalar reference matches RFC 8439 vector");

    // Emit reference keystream for the lab's key/nonce.
    let key = [7u8;32]; let nonce = [3u8;12];
    let mut ks = Vec::new();
    for c in 0..16u32 { ks.extend_from_slice(&block(&key,&nonce,c)); }
    let hex: String = ks[..1000].iter().map(|b| format!("{b:02x}")).collect();
    println!("{hex}");
}
