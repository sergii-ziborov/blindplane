import Foundation
import Metal

let src = """
#include <metal_stdlib>
using namespace metal;
#define ROTL(v,n) (((v) << (n)) | ((v) >> (32-(n))))

kernel void nop(device uint *o [[buffer(0)]], uint g [[thread_position_in_grid]]) {}

#define QR(a,b,c,d) \\
    a += b; d ^= a; d = ROTL(d,16); \\
    c += d; b ^= c; b = ROTL(b,12); \\
    a += b; d ^= a; d = ROTL(d, 8); \\
    c += d; b ^= c; b = ROTL(b, 7);

kernel void chacha20_xor(device uint4 *out [[buffer(0)]],
                         constant uint *k [[buffer(1)]],
                         device const uint4 *inp [[buffer(2)]],
                         uint gid [[thread_position_in_grid]]) {
    uint ctr = gid;
    uint x0=0x61707865u,x1=0x3320646eu,x2=0x79622d32u,x3=0x6b206574u;
    uint x4=k[0],x5=k[1],x6=k[2],x7=k[3],x8=k[4],x9=k[5],x10=k[6],x11=k[7];
    uint x12=ctr,x13=k[8],x14=k[9],x15=k[10];
    uint s0=x0,s1=x1,s2=x2,s3=x3,s4=x4,s5=x5,s6=x6,s7=x7;
    uint s8=x8,s9=x9,s10=x10,s11=x11,s12=x12,s13=x13,s14=x14,s15=x15;
    for (int r=0;r<10;++r) {
        QR(x0,x4,x8,x12) QR(x1,x5,x9,x13) QR(x2,x6,x10,x14) QR(x3,x7,x11,x15)
        QR(x0,x5,x10,x15) QR(x1,x6,x11,x12) QR(x2,x7,x8,x13) QR(x3,x4,x9,x14)
    }
    x0+=s0;x1+=s1;x2+=s2;x3+=s3;x4+=s4;x5+=s5;x6+=s6;x7+=s7;
    x8+=s8;x9+=s9;x10+=s10;x11+=s11;x12+=s12;x13+=s13;x14+=s14;x15+=s15;
    out[gid*4+0]=inp[gid*4+0]^uint4(x0,x1,x2,x3);
    out[gid*4+1]=inp[gid*4+1]^uint4(x4,x5,x6,x7);
    out[gid*4+2]=inp[gid*4+2]^uint4(x8,x9,x10,x11);
    out[gid*4+3]=inp[gid*4+3]^uint4(x12,x13,x14,x15);
}

// ============ BITSLICED AES-128 (constant time by construction) ============
// Kasper-Schwabe layout: 8 bit-planes x 128 bits, held as 8 x uint4 registers,
// processing 8 AES blocks (128 bytes) per thread. Every operation is a bitwise
// op on uint4 -> no table lookups, no data-dependent branches or addresses.
// Gate counts follow Boyar-Peralta (113-gate S-box) + KS MixColumns.
// NOTE: the middle/bottom S-box wiring below is gate-count-faithful; this kernel
// is a THROUGHPUT probe, output correctness is not claimed.

#define BP_SBOX(U0,U1,U2,U3,U4,U5,U6,U7, S0,S1,S2,S3,S4,S5,S6,S7) { \\
  /* top linear transform: 23 XOR (real Boyar-Peralta wiring) */ \\
  uint4 y14=U3^U5, y13=U0^U6, y9=U0^U3, y8=U0^U5, t0=U1^U2; \\
  uint4 y1=t0^U7, y4=y1^U3, y12=y13^y14, y2=y1^U0, y5=y1^U6; \\
  uint4 y3=y5^y8, t1=U4^y12, y15=t1^U5, y20=t1^U1, y6=y15^U7; \\
  uint4 y10=y15^t0, y11=y20^y9, y7=U7^y11, y17=y10^y11, y19=y10^y8; \\
  uint4 y16=t0^y11, y21=y13^y16, y18=U0^y16; \\
  /* middle non-linear: 30 AND + 53 XOR */ \\
  uint4 t2=y12&y15, t3=y3&y6, t4=t3^t2, t5=y4&U7, t6=t5^t2; \\
  uint4 t7=y13&y16, t8=y5&y1, t9=t8^t7, t10=y2&y7, t11=t10^t7; \\
  uint4 t12=y9&y11, t13=y14&y17, t14=t13^t12, t15=y8&y10, t16=t15^t12; \\
  uint4 t17=t4^t14, t18=t6^t16, t19=t9^t14, t20=t11^t16, t21=t17^y20; \\
  uint4 t22=t18^y19, t23=t19^y21, t24=t20^y18, t25=t21^t22, t26=t21&t23; \\
  uint4 t27=t24^t26, t28=t25&t27, t29=t28^t22, t30=t23^t24, t31=t22^t26; \\
  uint4 t32=t31&t30, t33=t32^t24, t34=t23^t33, t35=t27^t33, t36=t24&t35; \\
  uint4 t37=t36^t34, t38=t27^t36, t39=t29&t38, t40=t25^t39, t41=t40^t37; \\
  uint4 t42=t29^t33, t43=t29^t40, t44=t33^t37, t45=t42^t41, z0=t44&y15; \\
  uint4 z1=t37&y6, z2=t33&U7, z3=t43&y16, z4=t40&y1, z5=t29&y7; \\
  uint4 z6=t42&y11, z7=t45&y17, z8=t41&y10, z9=t44&y12, z10=t37&y3; \\
  uint4 z11=t33&y4, z12=t43&y13, z13=t40&y5, z14=t29&y2, z15=t42&y9; \\
  uint4 z16=t45&y14, z17=t41&y8; \\
  /* bottom linear transform: 26 XOR */ \\
  uint4 u0=z15^z16, u1=z10^z12, u2=z9^z10, u3=z0^z2, u4=z1^z3; \\
  uint4 u5=z14^u0, u6=z13^u1, u7=z5^u2, u8=z6^u3, u9=z7^u4; \\
  uint4 u10=z8^u5, u11=z4^u6, u12=z11^u7, u13=z17^u8, u14=u9^u10; \\
  uint4 u15=u11^u12, u16=u13^u14, u17=u15^u16, u18=u0^u17, u19=u1^u18; \\
  uint4 u20=u2^u19, u21=u3^u20, u22=u4^u21, u23=u5^u22, u24=u6^u23; \\
  uint4 u25=u7^u24; \\
  S0=u17; S1=u18; S2=~u19; S3=u20; S4=u21; S5=~u22; S6=u23; S7=u24^u25; \\
}

// ShiftRows on the KS layout: fixed byte rotate per row inside each 128-bit plane
#define SHIFTROWS_PLANE(q) { \\
  uint4 a = q; \\
  uint m0 = a.x, m1 = a.y, m2 = a.z, m3 = a.w; \\
  m1 = ROTL(m1, 8); m2 = ROTL(m2, 16); m3 = ROTL(m3, 24); \\
  q = uint4(m0, m1, m2, m3); \\
}

kernel void aes128_bitsliced(device uint4 *out [[buffer(0)]],
                             device const uint4 *inp [[buffer(2)]],
                             constant uint4 *rk [[buffer(1)]],
                             uint gid [[thread_position_in_grid]]) {
    uint4 q[8];
    for (int i = 0; i < 8; ++i) q[i] = inp[gid*8 + i];

    for (int r = 0; r < 10; ++r) {
        // AddRoundKey: 8 XOR
        for (int i = 0; i < 8; ++i) q[i] ^= rk[(r*8 + i) & 63];
        // SubBytes: 113 gates
        uint4 s0,s1,s2,s3,s4,s5,s6,s7;
        BP_SBOX(q[0],q[1],q[2],q[3],q[4],q[5],q[6],q[7], s0,s1,s2,s3,s4,s5,s6,s7)
        q[0]=s0;q[1]=s1;q[2]=s2;q[3]=s3;q[4]=s4;q[5]=s5;q[6]=s6;q[7]=s7;
        // ShiftRows
        for (int i = 0; i < 8; ++i) SHIFTROWS_PLANE(q[i])
        // MixColumns (KS): ~43 XOR + rotates on the 8 planes
        if (r < 9) {
            uint4 t[8];
            for (int i = 0; i < 8; ++i) {
                uint4 a = q[i];
                uint4 b = uint4(ROTL(a.x,8), ROTL(a.y,8), ROTL(a.z,8), ROTL(a.w,8));
                t[i] = a ^ b;
            }
            uint4 c0 = t[7];
            q[0] = t[0] ^ c0 ^ uint4(ROTL(q[0].x,16),ROTL(q[0].y,16),ROTL(q[0].z,16),ROTL(q[0].w,16));
            q[1] = t[1] ^ t[0] ^ c0 ^ uint4(ROTL(q[1].x,16),ROTL(q[1].y,16),ROTL(q[1].z,16),ROTL(q[1].w,16));
            q[2] = t[2] ^ t[1] ^ uint4(ROTL(q[2].x,16),ROTL(q[2].y,16),ROTL(q[2].z,16),ROTL(q[2].w,16));
            q[3] = t[3] ^ t[2] ^ c0 ^ uint4(ROTL(q[3].x,16),ROTL(q[3].y,16),ROTL(q[3].z,16),ROTL(q[3].w,16));
            q[4] = t[4] ^ t[3] ^ c0 ^ uint4(ROTL(q[4].x,16),ROTL(q[4].y,16),ROTL(q[4].z,16),ROTL(q[4].w,16));
            q[5] = t[5] ^ t[4] ^ uint4(ROTL(q[5].x,16),ROTL(q[5].y,16),ROTL(q[5].z,16),ROTL(q[5].w,16));
            q[6] = t[6] ^ t[5] ^ uint4(ROTL(q[6].x,16),ROTL(q[6].y,16),ROTL(q[6].z,16),ROTL(q[6].w,16));
            q[7] = t[7] ^ t[6] ^ uint4(ROTL(q[7].x,16),ROTL(q[7].y,16),ROTL(q[7].z,16),ROTL(q[7].w,16));
        }
    }
    for (int i = 0; i < 8; ++i) q[i] ^= rk[(80 + i) & 63];
    for (int i = 0; i < 8; ++i) out[gid*8 + i] = q[i];
}

kernel void aes256_bitsliced(device uint4 *out [[buffer(0)]],
                             device const uint4 *inp [[buffer(2)]],
                             constant uint4 *rk [[buffer(1)]],
                             uint gid [[thread_position_in_grid]]) {
    uint4 q[8];
    for (int i = 0; i < 8; ++i) q[i] = inp[gid*8 + i];

    for (int r = 0; r < 14; ++r) {
        // AddRoundKey: 8 XOR
        for (int i = 0; i < 8; ++i) q[i] ^= rk[(r*8 + i) & 63];
        // SubBytes: 113 gates
        uint4 s0,s1,s2,s3,s4,s5,s6,s7;
        BP_SBOX(q[0],q[1],q[2],q[3],q[4],q[5],q[6],q[7], s0,s1,s2,s3,s4,s5,s6,s7)
        q[0]=s0;q[1]=s1;q[2]=s2;q[3]=s3;q[4]=s4;q[5]=s5;q[6]=s6;q[7]=s7;
        // ShiftRows
        for (int i = 0; i < 8; ++i) SHIFTROWS_PLANE(q[i])
        // MixColumns (KS): ~43 XOR + rotates on the 8 planes
        if (r < 13) {
            uint4 t[8];
            for (int i = 0; i < 8; ++i) {
                uint4 a = q[i];
                uint4 b = uint4(ROTL(a.x,8), ROTL(a.y,8), ROTL(a.z,8), ROTL(a.w,8));
                t[i] = a ^ b;
            }
            uint4 c0 = t[7];
            q[0] = t[0] ^ c0 ^ uint4(ROTL(q[0].x,16),ROTL(q[0].y,16),ROTL(q[0].z,16),ROTL(q[0].w,16));
            q[1] = t[1] ^ t[0] ^ c0 ^ uint4(ROTL(q[1].x,16),ROTL(q[1].y,16),ROTL(q[1].z,16),ROTL(q[1].w,16));
            q[2] = t[2] ^ t[1] ^ uint4(ROTL(q[2].x,16),ROTL(q[2].y,16),ROTL(q[2].z,16),ROTL(q[2].w,16));
            q[3] = t[3] ^ t[2] ^ c0 ^ uint4(ROTL(q[3].x,16),ROTL(q[3].y,16),ROTL(q[3].z,16),ROTL(q[3].w,16));
            q[4] = t[4] ^ t[3] ^ c0 ^ uint4(ROTL(q[4].x,16),ROTL(q[4].y,16),ROTL(q[4].z,16),ROTL(q[4].w,16));
            q[5] = t[5] ^ t[4] ^ uint4(ROTL(q[5].x,16),ROTL(q[5].y,16),ROTL(q[5].z,16),ROTL(q[5].w,16));
            q[6] = t[6] ^ t[5] ^ uint4(ROTL(q[6].x,16),ROTL(q[6].y,16),ROTL(q[6].z,16),ROTL(q[6].w,16));
            q[7] = t[7] ^ t[6] ^ uint4(ROTL(q[7].x,16),ROTL(q[7].y,16),ROTL(q[7].z,16),ROTL(q[7].w,16));
        }
    }
    for (int i = 0; i < 8; ++i) q[i] ^= rk[(112 + i) & 63];
    for (int i = 0; i < 8; ++i) out[gid*8 + i] = q[i];
}

// ============ GHASH: constant-time GF(2^128) mul, no PMULL on GPU ============
// bit-serial carryless multiply 32x32 -> 64, constant time (no data-dep branch)
inline void clmul32(uint a, uint b, thread uint &lo, thread uint &hi) {
    uint l = 0, h = 0;
    for (uint i = 0; i < 32; ++i) {
        uint m = (uint)(0u - ((b >> i) & 1u));   // mask, branch-free
        l ^= (a << i) & m;
        h ^= (i == 0 ? 0u : (a >> (32 - i))) & m;
    }
    lo = l; hi = h;
}

kernel void ghash_ct(device uint4 *out [[buffer(0)]],
                     device const uint4 *inp [[buffer(2)]],
                     constant uint *H [[buffer(1)]],
                     uint gid [[thread_position_in_grid]]) {
    uint4 x = inp[gid];
    uint a[4] = { x.x, x.y, x.z, x.w };
    uint b[4] = { H[0], H[1], H[2], H[3] };
    uint acc[8] = {0,0,0,0,0,0,0,0};
    // schoolbook 128x128 carryless: 16 clmul32
    for (uint i = 0; i < 4; ++i) {
        for (uint j = 0; j < 4; ++j) {
            uint lo, hi;
            clmul32(a[i], b[j], lo, hi);
            acc[i+j]   ^= lo;
            acc[i+j+1] ^= hi;
        }
    }
    // reduction mod x^128 + x^7 + x^2 + x + 1 (shape-faithful)
    for (uint k = 7; k >= 4; --k) {
        uint v = acc[k];
        acc[k-4] ^= v ^ (v << 1) ^ (v << 2) ^ (v << 7);
        acc[k-3] ^= (v >> 31) ^ (v >> 30) ^ (v >> 25);
        acc[k] = 0;
    }
    out[gid] = uint4(acc[0], acc[1], acc[2], acc[3]);
}

// ============ 32x32->64 multiply throughput (Poly1305 relevance) ============
kernel void mulprobe(device uint *out [[buffer(0)]],
                     constant uint *k [[buffer(1)]],
                     uint gid [[thread_position_in_grid]]) {
    uint a = gid ^ k[0], b = gid + k[1], c = 0, d = 0;
    for (int i = 0; i < 128; ++i) {
        uint lo = a * b;
        uint hi = mulhi(a, b);
        c ^= lo; d ^= hi;
        a = lo ^ 0x9e3779b9u; b = hi + 1u;
    }
    if ((c ^ d) == 0xdeadbeefu) out[gid] = 1;
}
"""

func die(_ m: String) -> Never { FileHandle.standardError.write((m+"\n").data(using:.utf8)!); exit(1) }
guard let dev = MTLCreateSystemDefaultDevice(), let q = dev.makeCommandQueue() else { die("no metal") }
let lib: MTLLibrary
do { lib = try dev.makeLibrary(source: src, options: nil) } catch { die("compile: \(error)") }
func pipe(_ n: String) -> MTLComputePipelineState {
    guard let f = lib.makeFunction(name: n) else { die("no fn \(n)") }
    return try! dev.makeComputePipelineState(function: f)
}
let pNop = pipe("nop"), pXor = pipe("chacha20_xor"), pBs = pipe("aes128_bitsliced")
let pGh = pipe("ghash_ct"), pMul = pipe("mulprobe")
let pBs256 = pipe("aes256_bitsliced")
func buf(_ n: Int) -> MTLBuffer { dev.makeBuffer(length: n, options: .storageModeShared)! }
let MAXB = 128 << 20
let bOut = buf(MAXB), bIn = buf(MAXB), bK = buf(4096)
memset(bIn.contents(), 0x5a, MAXB); memset(bK.contents(), 0x37, 4096)
func now() -> Double { Double(DispatchTime.now().uptimeNanoseconds) * 1e-9 }

print("device: \(dev.name)")
for (n,p) in [("chacha20_xor",pXor),("aes128_bitsliced",pBs),("ghash_ct",pGh)] {
    print("  \(n): maxTPTG=\(p.maxTotalThreadsPerThreadgroup) (lower = higher register pressure)")
}

let mode = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "all"

func dispatch(_ cb: MTLCommandBuffer, _ p: MTLComputePipelineState, _ threads: Int) {
    let e = cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(p)
    e.setBuffer(bOut, offset:0, index:0); e.setBuffer(bK, offset:0, index:1); e.setBuffer(bIn, offset:0, index:2)
    let tg = min(p.maxTotalThreadsPerThreadgroup, 256)
    e.dispatchThreads(MTLSize(width:threads,height:1,depth:1), threadsPerThreadgroup: MTLSize(width:min(tg,threads),height:1,depth:1))
    e.endEncoding()
}
func tput(_ p: MTLComputePipelineState, bytes: Int, bpt: Int) -> Double {
    let threads = bytes / bpt
    for _ in 0..<3 { let cb = q.makeCommandBuffer()!; dispatch(cb,p,threads); cb.commit(); cb.waitUntilCompleted() }
    var iters = max(1, Int(0.4 / max(1e-7, Double(bytes)/2e10))); iters = min(iters, 8000)
    let t0 = now(); let cb = q.makeCommandBuffer()!
    for _ in 0..<iters { dispatch(cb,p,threads) }
    cb.commit(); cb.waitUntilCompleted()
    return Double(bytes*iters)/(now()-t0)/1e9
}

if mode == "all" || mode == "lat" {
    print("\n=== A. launch latency with the GPU already HOT (background load keeps clocks up) ===")
    let keepGoing = UnsafeMutablePointer<Bool>.allocate(capacity: 1); keepGoing.pointee = true
    let bg = Thread {
        let q2 = dev.makeCommandQueue()!
        while keepGoing.pointee {
            let cb = q2.makeCommandBuffer()!
            let e = cb.makeComputeCommandEncoder()!
            e.setComputePipelineState(pXor)
            e.setBuffer(bOut, offset: 0, index: 0); e.setBuffer(bK, offset:0, index:1); e.setBuffer(bIn, offset:0, index:2)
            e.dispatchThreads(MTLSize(width: 65536,height:1,depth:1), threadsPerThreadgroup: MTLSize(width:256,height:1,depth:1))
            e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
        }
    }
    bg.start()
    Thread.sleep(forTimeInterval: 0.6)
    var s = [Double]()
    for _ in 0..<3000 {
        let t0 = now()
        let cb = q.makeCommandBuffer()!; dispatch(cb, pNop, 1); cb.commit(); cb.waitUntilCompleted()
        s.append(now()-t0)
    }
    keepGoing.pointee = false
    s.sort()
    print(String(format: "  hot-GPU empty-kernel round trip: min %.2f us  p50 %.2f us  p99 %.2f us",
                 s[0]*1e6, s[1500]*1e6, s[2970]*1e6))
    Thread.sleep(forTimeInterval: 0.3)
}

if mode == "all" || mode == "tput" {
    print("\n=== B. constant-time kernels: bitsliced AES-128 and GHASH ===")
    print("  size        chacha20      AES-128 bitsliced   GHASH(CT, no PMULL)")
    for s in [1<<20, 4<<20, 16<<20, 64<<20] {
        let a = tput(pXor, bytes: s, bpt: 64)
        let b = tput(pBs,  bytes: s, bpt: 128)
        let c = tput(pGh,  bytes: s, bpt: 16)
        print(String(format: "  %9d  %8.2f GB/s   %8.2f GB/s      %8.3f GB/s", s, a, b, c))
    }
    // combined AES-GCM estimate = 1/(1/aes + 1/ghash)
    let a = tput(pBs, bytes: 16<<20, bpt: 128), g = tput(pGh, bytes: 16<<20, bpt: 16)
    print(String(format: "  => constant-time AES-128-GCM on GPU ~= %.2f GB/s (serial composition 1/(1/%.2f+1/%.3f))",
                 1.0/(1.0/a + 1.0/g), a, g))
    print(String(format: "  => AES-256 would be 14/10 rounds slower: ~%.2f GB/s", 1.0/(1.0/(a*10.0/14.0) + 1.0/g)))
}

if mode == "all" || mode == "mul" {
    print("\n=== C. 32x32 multiply throughput (Poly1305 / bignum relevance) ===")
    let threads = 1<<20, inner = 128, reps = 20
    for _ in 0..<3 { let cb = q.makeCommandBuffer()!; dispatch(cb,pMul,threads); cb.commit(); cb.waitUntilCompleted() }
    let t0 = now(); let cb = q.makeCommandBuffer()!
    for _ in 0..<reps { dispatch(cb,pMul,threads) }
    cb.commit(); cb.waitUntilCompleted()
    let dt = now()-t0
    let muls = Double(threads)*Double(inner)*2.0*Double(reps)  // mul + mulhi
    print(String(format: "  ~%.1f G 32-bit multiplies/s", muls/dt/1e9))
}

if mode == "aes256" {
    print("=== real 14-round AES-256 bitsliced (no extrapolation) ===")
    for s in [4<<20, 16<<20, 64<<20] {
        let a128 = tput(pBs, bytes: s, bpt: 128)
        let a256 = tput(pBs256, bytes: s, bpt: 128)
        print(String(format: "  %9d  AES-128 %6.2f GB/s   AES-256 %6.2f GB/s   ratio %.3f (10/14=0.714)", s, a128, a256, a256/a128))
    }
}

if mode == "bscontend" {
    let secs = Double(CommandLine.arguments[2])!
    let bytes = 16 << 20, threads = bytes/128
    for _ in 0..<3 { let cb = q.makeCommandBuffer()!; dispatch(cb,pBs256,threads); cb.commit(); cb.waitUntilCompleted() }
    let t0 = now(); var total = 0.0
    while now()-t0 < secs {
        let cb = q.makeCommandBuffer()!
        for _ in 0..<8 { dispatch(cb,pBs256,threads) }
        cb.commit(); cb.waitUntilCompleted()
        total += Double(bytes*8)
    }
    print(String(format: "GPU bitsliced AES-256 under this condition: %.2f GB/s", total/(now()-t0)/1e9))
}

if mode == "contend" {
    // run chacha20 flat out for N seconds, print achieved GB/s
    let secs = Double(CommandLine.arguments[2])!
    let bytes = 16 << 20, threads = bytes/64
    for _ in 0..<3 { let cb = q.makeCommandBuffer()!; dispatch(cb,pXor,threads); cb.commit(); cb.waitUntilCompleted() }
    let t0 = now(); var total = 0.0
    while now()-t0 < secs {
        let cb = q.makeCommandBuffer()!
        for _ in 0..<8 { dispatch(cb,pXor,threads) }
        cb.commit(); cb.waitUntilCompleted()
        total += Double(bytes*8)
    }
    print(String(format: "GPU chacha20 under this condition: %.2f GB/s", total/(now()-t0)/1e9))
}
