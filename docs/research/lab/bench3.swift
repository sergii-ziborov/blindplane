import Foundation
import Metal

let src = """
#include <metal_stdlib>
using namespace metal;
#define ROTL(v,n) (((v) << (n)) | ((v) >> (32-(n))))
#define QR(a,b,c,d) \\
    a += b; d ^= a; d = ROTL(d,16); \\
    c += d; b ^= c; b = ROTL(b,12); \\
    a += b; d ^= a; d = ROTL(d, 8); \\
    c += d; b ^= c; b = ROTL(b, 7);

kernel void nop(device uint *o [[buffer(0)]], uint g [[thread_position_in_grid]]) {}

// ---- Poly1305, 5 x 26-bit limbs, constant time. 1 KiB (64 blocks) per thread.
// Real parallel use would combine per-thread accumulators with powers of r; the
// per-block cost measured here is exactly the same either way.
#define POLY_BLOCKS 64
kernel void poly1305(device uint *out [[buffer(0)]],
                     constant uint *key [[buffer(1)]],
                     device const uint4 *inp [[buffer(2)]],
                     uint gid [[thread_position_in_grid]]) {
    uint r0 = key[0] & 0x3ffffffu;
    uint r1 = ((key[0] >> 26) | (key[1] << 6)) & 0x3ffff03u;
    uint r2 = ((key[1] >> 20) | (key[2] << 12)) & 0x3ffc0ffu;
    uint r3 = ((key[2] >> 14) | (key[3] << 18)) & 0x3f03fffu;
    uint r4 = (key[3] >> 8) & 0x00fffffu;
    uint s1 = r1*5, s2 = r2*5, s3 = r3*5, s4 = r4*5;
    uint h0=0,h1=0,h2=0,h3=0,h4=0;
    uint base = gid * POLY_BLOCKS;
    for (uint b = 0; b < POLY_BLOCKS; ++b) {
        uint4 m = inp[base + b];
        h0 += m.x & 0x3ffffffu;
        h1 += ((m.x >> 26) | (m.y << 6)) & 0x3ffffffu;
        h2 += ((m.y >> 20) | (m.z << 12)) & 0x3ffffffu;
        h3 += ((m.z >> 14) | (m.w << 18)) & 0x3ffffffu;
        h4 += (m.w >> 8) | (1u << 24);
        ulong d0 = (ulong)h0*r0 + (ulong)h1*s4 + (ulong)h2*s3 + (ulong)h3*s2 + (ulong)h4*s1;
        ulong d1 = (ulong)h0*r1 + (ulong)h1*r0 + (ulong)h2*s4 + (ulong)h3*s3 + (ulong)h4*s2;
        ulong d2 = (ulong)h0*r2 + (ulong)h1*r1 + (ulong)h2*r0 + (ulong)h3*s4 + (ulong)h4*s3;
        ulong d3 = (ulong)h0*r3 + (ulong)h1*r2 + (ulong)h2*r1 + (ulong)h3*r0 + (ulong)h4*s4;
        ulong d4 = (ulong)h0*r4 + (ulong)h1*r3 + (ulong)h2*r2 + (ulong)h3*r1 + (ulong)h4*r0;
        ulong c;
        c = d0 >> 26; h0 = (uint)d0 & 0x3ffffffu; d1 += c;
        c = d1 >> 26; h1 = (uint)d1 & 0x3ffffffu; d2 += c;
        c = d2 >> 26; h2 = (uint)d2 & 0x3ffffffu; d3 += c;
        c = d3 >> 26; h3 = (uint)d3 & 0x3ffffffu; d4 += c;
        c = d4 >> 26; h4 = (uint)d4 & 0x3ffffffu;
        h0 += (uint)c * 5u;
        c = h0 >> 26; h0 &= 0x3ffffffu; h1 += (uint)c;
    }
    out[gid] = h0 ^ h1 ^ h2 ^ h3 ^ h4;
}

// ---- full ChaCha20-Poly1305 AEAD: 1 KiB per thread (16 chacha blocks + 64 poly blocks)
kernel void chacha20poly1305(device uint4 *out [[buffer(0)]],
                             constant uint *key [[buffer(1)]],
                             device const uint4 *inp [[buffer(2)]],
                             device uint *tags [[buffer(3)]],
                             uint gid [[thread_position_in_grid]]) {
    uint r0 = key[0] & 0x3ffffffu;
    uint r1 = ((key[0] >> 26) | (key[1] << 6)) & 0x3ffff03u;
    uint r2 = ((key[1] >> 20) | (key[2] << 12)) & 0x3ffc0ffu;
    uint r3 = ((key[2] >> 14) | (key[3] << 18)) & 0x3f03fffu;
    uint r4 = (key[3] >> 8) & 0x00fffffu;
    uint s1 = r1*5, s2 = r2*5, s3 = r3*5, s4 = r4*5;
    uint h0=0,h1=0,h2=0,h3=0,h4=0;
    uint cbase = gid * 16;          // 16 chacha blocks of 64B = 1 KiB
    for (uint blk = 0; blk < 16; ++blk) {
        uint ctr = cbase + blk;
        uint x0=0x61707865u,x1=0x3320646eu,x2=0x79622d32u,x3=0x6b206574u;
        uint x4=key[0],x5=key[1],x6=key[2],x7=key[3];
        uint x8=key[4],x9=key[5],x10=key[6],x11=key[7];
        uint x12=ctr,x13=key[8],x14=key[9],x15=key[10];
        uint z0=x0,z1=x1,z2=x2,z3=x3,z4=x4,z5=x5,z6=x6,z7=x7;
        uint z8=x8,z9=x9,z10=x10,z11=x11,z12=x12,z13=x13,z14=x14,z15=x15;
        for (int r=0;r<10;++r) {
            QR(x0,x4,x8,x12) QR(x1,x5,x9,x13) QR(x2,x6,x10,x14) QR(x3,x7,x11,x15)
            QR(x0,x5,x10,x15) QR(x1,x6,x11,x12) QR(x2,x7,x8,x13) QR(x3,x4,x9,x14)
        }
        x0+=z0;x1+=z1;x2+=z2;x3+=z3;x4+=z4;x5+=z5;x6+=z6;x7+=z7;
        x8+=z8;x9+=z9;x10+=z10;x11+=z11;x12+=z12;x13+=z13;x14+=z14;x15+=z15;
        uint4 ks[4];
        ks[0]=uint4(x0,x1,x2,x3); ks[1]=uint4(x4,x5,x6,x7);
        ks[2]=uint4(x8,x9,x10,x11); ks[3]=uint4(x12,x13,x14,x15);
        for (uint j = 0; j < 4; ++j) {
            uint4 ct = inp[cbase*4 + blk*4 + j] ^ ks[j];
            out[cbase*4 + blk*4 + j] = ct;
            // MAC the ciphertext
            h0 += ct.x & 0x3ffffffu;
            h1 += ((ct.x >> 26) | (ct.y << 6)) & 0x3ffffffu;
            h2 += ((ct.y >> 20) | (ct.z << 12)) & 0x3ffffffu;
            h3 += ((ct.z >> 14) | (ct.w << 18)) & 0x3ffffffu;
            h4 += (ct.w >> 8) | (1u << 24);
            ulong d0 = (ulong)h0*r0 + (ulong)h1*s4 + (ulong)h2*s3 + (ulong)h3*s2 + (ulong)h4*s1;
            ulong d1 = (ulong)h0*r1 + (ulong)h1*r0 + (ulong)h2*s4 + (ulong)h3*s3 + (ulong)h4*s2;
            ulong d2 = (ulong)h0*r2 + (ulong)h1*r1 + (ulong)h2*r0 + (ulong)h3*s4 + (ulong)h4*s3;
            ulong d3 = (ulong)h0*r3 + (ulong)h1*r2 + (ulong)h2*r1 + (ulong)h3*r0 + (ulong)h4*s4;
            ulong d4 = (ulong)h0*r4 + (ulong)h1*r3 + (ulong)h2*r2 + (ulong)h3*r1 + (ulong)h4*r0;
            ulong c;
            c = d0 >> 26; h0 = (uint)d0 & 0x3ffffffu; d1 += c;
            c = d1 >> 26; h1 = (uint)d1 & 0x3ffffffu; d2 += c;
            c = d2 >> 26; h2 = (uint)d2 & 0x3ffffffu; d3 += c;
            c = d3 >> 26; h3 = (uint)d3 & 0x3ffffffu; d4 += c;
            c = d4 >> 26; h4 = (uint)d4 & 0x3ffffffu;
            h0 += (uint)c * 5u;
            c = h0 >> 26; h0 &= 0x3ffffffu; h1 += (uint)c;
        }
    }
    tags[gid] = h0 ^ h1 ^ h2 ^ h3 ^ h4;
}
"""

func die(_ m: String) -> Never { FileHandle.standardError.write((m+"\n").data(using:.utf8)!); exit(1) }
guard let dev = MTLCreateSystemDefaultDevice(), let q = dev.makeCommandQueue() else { die("no metal") }
let lib = try! dev.makeLibrary(source: src, options: nil)
func pipe(_ n: String) -> MTLComputePipelineState {
    try! dev.makeComputePipelineState(function: lib.makeFunction(name: n)!)
}
let pNop = pipe("nop"), pPoly = pipe("poly1305"), pAead = pipe("chacha20poly1305")
func buf(_ n: Int) -> MTLBuffer { dev.makeBuffer(length: n, options: .storageModeShared)! }
let MAXB = 128 << 20
let bOut = buf(MAXB), bIn = buf(MAXB), bK = buf(4096), bTag = buf(8 << 20)
memset(bIn.contents(), 0x5a, MAXB); memset(bK.contents(), 0x37, 4096)
func now() -> Double { Double(DispatchTime.now().uptimeNanoseconds) * 1e-9 }

func dispatch(_ cb: MTLCommandBuffer, _ p: MTLComputePipelineState, _ threads: Int) {
    let e = cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(p)
    e.setBuffer(bOut, offset:0, index:0); e.setBuffer(bK, offset:0, index:1)
    e.setBuffer(bIn, offset:0, index:2); e.setBuffer(bTag, offset:0, index:3)
    let tg = min(p.maxTotalThreadsPerThreadgroup, 256)
    e.dispatchThreads(MTLSize(width:threads,height:1,depth:1),
                      threadsPerThreadgroup: MTLSize(width:min(tg,threads),height:1,depth:1))
    e.endEncoding()
}
func tput(_ p: MTLComputePipelineState, bytes: Int, bpt: Int) -> Double {
    let threads = bytes/bpt
    for _ in 0..<3 { let cb = q.makeCommandBuffer()!; dispatch(cb,p,threads); cb.commit(); cb.waitUntilCompleted() }
    var iters = max(1, Int(0.4 / max(1e-7, Double(bytes)/2e10))); iters = min(iters, 8000)
    let t0 = now(); let cb = q.makeCommandBuffer()!
    for _ in 0..<iters { dispatch(cb,p,threads) }
    cb.commit(); cb.waitUntilCompleted()
    return Double(bytes*iters)/(now()-t0)/1e9
}

let mode = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "all"

if mode == "all" {
    print("device: \(dev.name)")
    print("  poly1305 maxTPTG=\(pPoly.maxTotalThreadsPerThreadgroup)  aead maxTPTG=\(pAead.maxTotalThreadsPerThreadgroup)")

    print("\n=== D. where does the launch latency actually go? ===")
    // separate GPU execution window from CPU-side wait/wakeup
    var wall = [Double](), gpu = [Double](), sched = [Double]()
    for _ in 0..<2000 {
        let t0 = now()
        let cb = q.makeCommandBuffer()!
        dispatch(cb, pNop, 1)
        let tCommit = now()
        cb.commit()
        cb.waitUntilCompleted()
        wall.append(now()-t0)
        gpu.append(cb.gpuEndTime - cb.gpuStartTime)
        sched.append(cb.gpuStartTime - cb.kernelStartTime > 0 ? cb.gpuStartTime - cb.kernelStartTime : 0)
        _ = tCommit
    }
    wall.sort(); gpu.sort(); sched.sort()
    print(String(format: "  wall commit->completed : min %7.2f us  p50 %7.2f us", wall[0]*1e6, wall[1000]*1e6))
    print(String(format: "  GPU execution window   : min %7.2f us  p50 %7.2f us", gpu[0]*1e6, gpu[1000]*1e6))
    print(String(format: "  kernelStart->gpuStart  : min %7.2f us  p50 %7.2f us", sched[0]*1e6, sched[1000]*1e6))
    print("  (difference = driver submission + CPU thread wakeup; unavoidable per dispatch)")

    print("\n=== E. ChaCha20-Poly1305 fully on GPU (constant time, no tables) ===")
    print("  size        Poly1305 alone   ChaCha20-Poly1305 AEAD")
    for s in [1<<20, 4<<20, 16<<20, 64<<20] {
        let p = tput(pPoly, bytes: s, bpt: 1024)
        let a = tput(pAead, bytes: s, bpt: 1024)
        print(String(format: "  %9d  %8.2f GB/s      %8.2f GB/s", s, p, a))
    }
}

if mode == "contend" {
    let secs = Double(CommandLine.arguments[2])!
    let bytes = 16 << 20, threads = bytes/1024
    for _ in 0..<3 { let cb = q.makeCommandBuffer()!; dispatch(cb,pAead,threads); cb.commit(); cb.waitUntilCompleted() }
    let t0 = now(); var total = 0.0
    while now()-t0 < secs {
        let cb = q.makeCommandBuffer()!
        for _ in 0..<8 { dispatch(cb,pAead,threads) }
        cb.commit(); cb.waitUntilCompleted()
        total += Double(bytes*8)
    }
    print(String(format: "GPU ChaCha20-Poly1305: %.2f GB/s", total/(now()-t0)/1e9))
}
