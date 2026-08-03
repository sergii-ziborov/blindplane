import Foundation
import Metal

// ---------------------------------------------------------------- shader src
let src = """
#include <metal_stdlib>
using namespace metal;

kernel void nop(device uint *out [[buffer(0)]], uint gid [[thread_position_in_grid]]) { }

kernel void touch1(device uint *out [[buffer(0)]], uint gid [[thread_position_in_grid]]) {
    if (gid == 0) out[0] = out[0] + 1;
}

// pure streaming: read 16B, xor, write 16B  -> memory roofline for in-place AEAD
kernel void streamxor(device uint4 *out [[buffer(0)]],
                      device const uint4 *inp [[buffer(1)]],
                      uint gid [[thread_position_in_grid]]) {
    out[gid] = inp[gid] ^ uint4(0x9e3779b9u);
}

#define ROTL(v,n) (((v) << (n)) | ((v) >> (32-(n))))
#define QR(a,b,c,d) \\
    a += b; d ^= a; d = ROTL(d,16); \\
    c += d; b ^= c; b = ROTL(b,12); \\
    a += b; d ^= a; d = ROTL(d, 8); \\
    c += d; b ^= c; b = ROTL(b, 7);

#define CHACHA_BODY \\
    uint x0=0x61707865u, x1=0x3320646eu, x2=0x79622d32u, x3=0x6b206574u; \\
    uint x4=k[0], x5=k[1], x6=k[2], x7=k[3]; \\
    uint x8=k[4], x9=k[5], x10=k[6], x11=k[7]; \\
    uint x12=ctr, x13=k[8], x14=k[9], x15=k[10]; \\
    uint s0=x0,s1=x1,s2=x2,s3=x3,s4=x4,s5=x5,s6=x6,s7=x7; \\
    uint s8=x8,s9=x9,s10=x10,s11=x11,s12=x12,s13=x13,s14=x14,s15=x15; \\
    for (int r = 0; r < 10; ++r) { \\
        QR(x0,x4,x8,x12) QR(x1,x5,x9,x13) QR(x2,x6,x10,x14) QR(x3,x7,x11,x15) \\
        QR(x0,x5,x10,x15) QR(x1,x6,x11,x12) QR(x2,x7,x8,x13) QR(x3,x4,x9,x14) \\
    } \\
    x0+=s0;x1+=s1;x2+=s2;x3+=s3;x4+=s4;x5+=s5;x6+=s6;x7+=s7; \\
    x8+=s8;x9+=s9;x10+=s10;x11+=s11;x12+=s12;x13+=s13;x14+=s14;x15+=s15;

// keystream only (compute bound, write 64B per thread)
kernel void chacha20_ks(device uint4 *out [[buffer(0)]],
                        constant uint *k [[buffer(1)]],
                        uint gid [[thread_position_in_grid]]) {
    uint ctr = gid;
    CHACHA_BODY
    out[gid*4+0] = uint4(x0,x1,x2,x3);
    out[gid*4+1] = uint4(x4,x5,x6,x7);
    out[gid*4+2] = uint4(x8,x9,x10,x11);
    out[gid*4+3] = uint4(x12,x13,x14,x15);
}

// full stream cipher: read 64B plaintext, xor, write 64B
kernel void chacha20_xor(device uint4 *out [[buffer(0)]],
                         device const uint4 *inp [[buffer(2)]],
                         constant uint *k [[buffer(1)]],
                         uint gid [[thread_position_in_grid]]) {
    uint ctr = gid;
    CHACHA_BODY
    out[gid*4+0] = inp[gid*4+0] ^ uint4(x0,x1,x2,x3);
    out[gid*4+1] = inp[gid*4+1] ^ uint4(x4,x5,x6,x7);
    out[gid*4+2] = inp[gid*4+2] ^ uint4(x8,x9,x10,x11);
    out[gid*4+3] = inp[gid*4+3] ^ uint4(x12,x13,x14,x15);
}

// ---- AES-128-CTR, T-table in threadgroup memory (NOT constant time; upper bound) ----
kernel void aes128ctr_ttab(device uint4 *out [[buffer(0)]],
                           device const uint4 *inp [[buffer(4)]],
                           constant uint *rk [[buffer(1)]],
                           device const uint *Te [[buffer(2)]],
                           constant uint *sboxw [[buffer(3)]],
                           threadgroup uint *T [[threadgroup(0)]],
                           uint gid [[thread_position_in_grid]],
                           uint lid [[thread_position_in_threadgroup]],
                           uint tgs [[threads_per_threadgroup]]) {
    // cooperative load of 4 x 256 words T-tables into threadgroup memory
    for (uint i = lid; i < 1024; i += tgs) T[i] = Te[i];
    threadgroup_barrier(mem_flags::mem_threadgroup);

    threadgroup uint *T0 = T;
    threadgroup uint *T1 = T + 256;
    threadgroup uint *T2 = T + 512;
    threadgroup uint *T3 = T + 768;

    uint s0 = gid ^ rk[0];
    uint s1 = 0x11111111u ^ rk[1];
    uint s2 = 0x22222222u ^ rk[2];
    uint s3 = 0x33333333u ^ rk[3];
    uint t0,t1,t2,t3;
    uint kk = 4;
    for (int r = 0; r < 4; ++r) {
        t0 = T0[s0&0xff]^T1[(s1>>8)&0xff]^T2[(s2>>16)&0xff]^T3[(s3>>24)&0xff]^rk[kk+0];
        t1 = T0[s1&0xff]^T1[(s2>>8)&0xff]^T2[(s3>>16)&0xff]^T3[(s0>>24)&0xff]^rk[kk+1];
        t2 = T0[s2&0xff]^T1[(s3>>8)&0xff]^T2[(s0>>16)&0xff]^T3[(s1>>24)&0xff]^rk[kk+2];
        t3 = T0[s3&0xff]^T1[(s0>>8)&0xff]^T2[(s1>>16)&0xff]^T3[(s2>>24)&0xff]^rk[kk+3];
        kk += 4;
        s0 = T0[t0&0xff]^T1[(t1>>8)&0xff]^T2[(t2>>16)&0xff]^T3[(t3>>24)&0xff]^rk[kk+0];
        s1 = T0[t1&0xff]^T1[(t2>>8)&0xff]^T2[(t3>>16)&0xff]^T3[(t0>>24)&0xff]^rk[kk+1];
        s2 = T0[t2&0xff]^T1[(t3>>8)&0xff]^T2[(t0>>16)&0xff]^T3[(t1>>24)&0xff]^rk[kk+2];
        s3 = T0[t3&0xff]^T1[(t0>>8)&0xff]^T2[(t1>>16)&0xff]^T3[(t2>>24)&0xff]^rk[kk+3];
        kk += 4;
    }
    // round 9
    t0 = T0[s0&0xff]^T1[(s1>>8)&0xff]^T2[(s2>>16)&0xff]^T3[(s3>>24)&0xff]^rk[40];
    t1 = T0[s1&0xff]^T1[(s2>>8)&0xff]^T2[(s3>>16)&0xff]^T3[(s0>>24)&0xff]^rk[41];
    t2 = T0[s2&0xff]^T1[(s3>>8)&0xff]^T2[(s0>>16)&0xff]^T3[(s1>>24)&0xff]^rk[42];
    t3 = T0[s3&0xff]^T1[(s0>>8)&0xff]^T2[(s1>>16)&0xff]^T3[(s2>>24)&0xff]^rk[43];
    // final round: sbox only
    s0 = (sboxw[t0&0xff]&0xffu) | (sboxw[(t1>>8)&0xff]&0xff00u) | (sboxw[(t2>>16)&0xff]&0xff0000u) | (sboxw[(t3>>24)&0xff]&0xff000000u);
    s1 = (sboxw[t1&0xff]&0xffu) | (sboxw[(t2>>8)&0xff]&0xff00u) | (sboxw[(t3>>16)&0xff]&0xff0000u) | (sboxw[(t0>>24)&0xff]&0xff000000u);
    s2 = (sboxw[t2&0xff]&0xffu) | (sboxw[(t3>>8)&0xff]&0xff00u) | (sboxw[(t0>>16)&0xff]&0xff0000u) | (sboxw[(t1>>24)&0xff]&0xff000000u);
    s3 = (sboxw[t3&0xff]&0xffu) | (sboxw[(t0>>8)&0xff]&0xff00u) | (sboxw[(t1>>16)&0xff]&0xff0000u) | (sboxw[(t2>>24)&0xff]&0xff000000u);
    out[gid] = inp[gid] ^ uint4(s0,s1,s2,s3);
}

// raw 32-bit integer ALU throughput probe (xor/and/shift mix, no memory)
kernel void aluprobe(device uint *out [[buffer(0)]],
                     constant uint *k [[buffer(1)]],
                     uint gid [[thread_position_in_grid]]) {
    uint a = gid ^ k[0], b = gid + k[1], c = gid * 2654435761u, d = gid ^ 0xa5a5a5a5u;
    for (int i = 0; i < 256; ++i) {
        a ^= b; a = ROTL(a, 7);  b += c;
        c ^= d; c = ROTL(c, 11); d += a;
        a &= 0xfffffffeu; a |= 1u;
        b ^= ROTL(c, 13);
        c ^= ROTL(d, 5);
        d ^= ROTL(a, 17);
    }
    if ((a ^ b ^ c ^ d) == 0xdeadbeefu) out[gid] = 1;
}
"""

// ---------------------------------------------------------------- host setup
func die(_ m: String) -> Never { FileHandle.standardError.write((m+"\n").data(using:.utf8)!); exit(1) }

guard let dev = MTLCreateSystemDefaultDevice() else { die("no metal device") }
guard let q = dev.makeCommandQueue() else { die("no queue") }
print("device: \(dev.name)  unified=\(dev.hasUnifiedMemory)  maxTG=\(dev.maxThreadsPerThreadgroup)")
print("recommendedMaxWorkingSetSize: \(dev.recommendedMaxWorkingSetSize/1024/1024) MiB")

let lib: MTLLibrary
do { lib = try dev.makeLibrary(source: src, options: nil) }
catch { die("shader compile failed: \(error)") }

func pipe(_ n: String) -> MTLComputePipelineState {
    guard let f = lib.makeFunction(name: n) else { die("no fn \(n)") }
    return try! dev.makeComputePipelineState(function: f)
}
let pNop = pipe("nop"), pTouch = pipe("touch1"), pStream = pipe("streamxor")
let pKs = pipe("chacha20_ks"), pXor = pipe("chacha20_xor")
let pAes = pipe("aes128ctr_ttab"), pAlu = pipe("aluprobe")

for (n,p) in [("nop",pNop),("streamxor",pStream),("chacha20_xor",pXor),("aes128ctr_ttab",pAes),("aluprobe",pAlu)] {
    print("pipeline \(n): maxThreadsPerThreadgroup=\(p.maxTotalThreadsPerThreadgroup) simdWidth=\(p.threadExecutionWidth)")
}

// ---- AES tables (real S-box computed in GF(2^8)) ----
func xtime(_ x: UInt8) -> UInt8 { (x << 1) ^ ((x & 0x80) != 0 ? 0x1b : 0) }
func gmul(_ a: UInt8, _ b: UInt8) -> UInt8 {
    var a = a, b = b, r: UInt8 = 0
    for _ in 0..<8 { if b & 1 != 0 { r ^= a }; a = xtime(a); b >>= 1 }
    return r
}
var sbox = [UInt8](repeating: 0, count: 256)
do {  // inverse table then affine
    var inv = [UInt8](repeating: 0, count: 256)
    for i in 1..<256 { for j in 1..<256 where gmul(UInt8(i), UInt8(j)) == 1 { inv[i] = UInt8(j) } }
    for i in 0..<256 {
        let b = inv[i]
        var s: UInt8 = 0
        for bit in 0..<8 {
            let v = ((b >> UInt8(bit)) & 1) ^ ((b >> UInt8((bit+4)%8)) & 1) ^ ((b >> UInt8((bit+5)%8)) & 1)
                  ^ ((b >> UInt8((bit+6)%8)) & 1) ^ ((b >> UInt8((bit+7)%8)) & 1) ^ ((0x63 >> UInt8(bit)) & 1)
            s |= (v & 1) << UInt8(bit)
        }
        sbox[i] = s
    }
}
var Te = [UInt32](repeating: 0, count: 1024)
for i in 0..<256 {
    let s = sbox[i]
    let w = UInt32(gmul(s,2)) | (UInt32(s) << 8) | (UInt32(s) << 16) | (UInt32(gmul(s,3)) << 24)
    Te[i] = w
    Te[256+i] = (w << 8) | (w >> 24)
    Te[512+i] = (w << 16) | (w >> 16)
    Te[768+i] = (w << 24) | (w >> 8)
}
var sboxw = [UInt32](repeating: 0, count: 256)
for i in 0..<256 { let s = UInt32(sbox[i]); sboxw[i] = s | (s<<8) | (s<<16) | (s<<24) }

var rk = [UInt32](repeating: 0, count: 44)
for i in 0..<44 { rk[i] = UInt32.random(in: 0...UInt32.max) }
var chKey = [UInt32](repeating: 0, count: 11)
for i in 0..<11 { chKey[i] = UInt32.random(in: 0...UInt32.max) }

func buf(_ bytes: Int) -> MTLBuffer { dev.makeBuffer(length: bytes, options: .storageModeShared)! }
func bufOf<T>(_ a: [T]) -> MTLBuffer { a.withUnsafeBytes { dev.makeBuffer(bytes: $0.baseAddress!, length: $0.count, options: .storageModeShared)! } }
let bTe = bufOf(Te), bSbox = bufOf(sboxw), bRk = bufOf(rk), bKey = bufOf(chKey)

let MAXB = 256 << 20
let bOut = buf(MAXB), bIn = buf(MAXB)
memset(bIn.contents(), 0x5a, MAXB)

func now() -> Double { Double(DispatchTime.now().uptimeNanoseconds) * 1e-9 }

// ------------------------------------------------- 1. launch overhead
print("\n=== 1. command-buffer launch overhead (commit -> completion, blocking) ===")
func launchLatency(_ p: MTLComputePipelineState, threads: Int, label: String, iters: Int = 2000) {
    var samples = [Double]()
    samples.reserveCapacity(iters)
    for _ in 0..<iters {
        let t0 = now()
        let cb = q.makeCommandBuffer()!
        let e = cb.makeComputeCommandEncoder()!
        e.setComputePipelineState(p)
        e.setBuffer(bOut, offset: 0, index: 0)
        e.setBuffer(bKey, offset: 0, index: 1)
        e.dispatchThreads(MTLSize(width: threads, height: 1, depth: 1),
                          threadsPerThreadgroup: MTLSize(width: min(threads,64), height: 1, depth: 1))
        e.endEncoding()
        cb.commit()
        cb.waitUntilCompleted()
        samples.append(now() - t0)
    }
    samples.sort()
    let mean = samples.reduce(0,+)/Double(iters)
    print(String(format: "  %-28s min %7.2f us  p50 %7.2f us  mean %7.2f us  p99 %7.2f us",
                 (label as NSString).utf8String!, samples[0]*1e6, samples[iters/2]*1e6, mean*1e6, samples[iters*99/100]*1e6))
}
launchLatency(pNop, threads: 1, label: "empty kernel, 1 thread")
launchLatency(pTouch, threads: 1, label: "1 thread, 1 store")
launchLatency(pNop, threads: 1024, label: "empty kernel, 1024 threads")

// encode-only cost
do {
    let iters = 5000
    let t0 = now()
    for _ in 0..<iters {
        let cb = q.makeCommandBuffer()!
        let e = cb.makeComputeCommandEncoder()!
        e.setComputePipelineState(pNop)
        e.setBuffer(bOut, offset: 0, index: 0)
        e.dispatchThreads(MTLSize(width:1,height:1,depth:1), threadsPerThreadgroup: MTLSize(width:1,height:1,depth:1))
        e.endEncoding()
        cb.commit()
    }
    let t1 = now()
    print(String(format: "  CPU-side encode+commit only (async): %.2f us/cb", (t1-t0)/Double(iters)*1e6))
}

// ------------------------------------------------- 2. throughput sweep
print("\n=== 2. throughput vs buffer size (steady state, N iterations timed together) ===")

func throughput(_ p: MTLComputePipelineState, bytes: Int, bytesPerThread: Int,
                tgMem: Int = 0, useIn: Bool, aes: Bool = false) -> Double {
    let threads = bytes / bytesPerThread
    let tgSize = min(p.maxTotalThreadsPerThreadgroup, 256)
    // warm
    for _ in 0..<3 {
        let cb = q.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
        e.setComputePipelineState(p)
        e.setBuffer(bOut, offset: 0, index: 0); e.setBuffer(bKey, offset: 0, index: 1)
        if aes { e.setBuffer(bRk, offset:0, index:1); e.setBuffer(bTe, offset:0, index:2); e.setBuffer(bSbox, offset:0, index:3); e.setBuffer(bIn, offset:0, index:4); e.setThreadgroupMemoryLength(4096, index:0) }
        else if useIn { e.setBuffer(bIn, offset: 0, index: p === pStream ? 1 : 2) ; if p === pXor { e.setBuffer(bKey, offset:0, index:1) } }
        e.dispatchThreads(MTLSize(width: threads,height:1,depth:1), threadsPerThreadgroup: MTLSize(width: tgSize,height:1,depth:1))
        e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    }
    let target = 0.35
    var iters = max(1, Int(target / max(1e-6, Double(bytes)/8e9)))
    iters = min(iters, 20000)
    let t0 = now()
    let cb = q.makeCommandBuffer()!
    for _ in 0..<iters {
        let e = cb.makeComputeCommandEncoder()!
        e.setComputePipelineState(p)
        e.setBuffer(bOut, offset: 0, index: 0); e.setBuffer(bKey, offset: 0, index: 1)
        if aes { e.setBuffer(bRk, offset:0, index:1); e.setBuffer(bTe, offset:0, index:2); e.setBuffer(bSbox, offset:0, index:3); e.setBuffer(bIn, offset:0, index:4); e.setThreadgroupMemoryLength(4096, index:0) }
        else if useIn { e.setBuffer(bIn, offset: 0, index: p === pStream ? 1 : 2); if p === pXor { e.setBuffer(bKey, offset:0, index:1) } }
        e.dispatchThreads(MTLSize(width: threads,height:1,depth:1), threadsPerThreadgroup: MTLSize(width: tgSize,height:1,depth:1))
        e.endEncoding()
    }
    cb.commit(); cb.waitUntilCompleted()
    let dt = now() - t0
    return Double(bytes * iters) / dt / 1e9
}

let sizes = [4096, 16384, 65536, 262144, 1<<20, 4<<20, 16<<20, 64<<20, 256<<20]
print("  size        streamxor    chacha20ks   chacha20xor  aes128ctr(T)")
for s in sizes {
    let a = throughput(pStream, bytes: s, bytesPerThread: 16, useIn: true)
    let b = throughput(pKs,     bytes: s, bytesPerThread: 64, useIn: false)
    let c = throughput(pXor,    bytes: s, bytesPerThread: 64, useIn: true)
    let d = throughput(pAes,    bytes: s, bytesPerThread: 16, useIn: true, aes: true)
    print(String(format: "  %8d   %8.2f GB/s %8.2f GB/s %8.2f GB/s %8.2f GB/s", s, a, b, c, d))
}

// ------------------------------------------------- 3. end-to-end latency for one record
print("\n=== 3. single-dispatch end-to-end latency (blocking, realistic per-record use) ===")
for s in [1024, 4096, 16384, 65536, 1<<20, 16<<20] {
    var best = Double.infinity, sum = 0.0
    let n = s <= (1<<20) ? 500 : 100
    for _ in 0..<n {
        let t0 = now()
        let cb = q.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
        e.setComputePipelineState(pXor)
        e.setBuffer(bOut, offset:0, index:0); e.setBuffer(bKey, offset:0, index:1); e.setBuffer(bIn, offset:0, index:2)
        let th = max(1, s/64)
        e.dispatchThreads(MTLSize(width:th,height:1,depth:1), threadsPerThreadgroup: MTLSize(width:min(th,256),height:1,depth:1))
        e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
        let dt = now()-t0; best = min(best,dt); sum += dt
    }
    print(String(format: "  %8d B  min %8.2f us  mean %8.2f us  -> effective %6.2f GB/s (mean)", s, best*1e6, sum/Double(n)*1e6, Double(s)/(sum/Double(n))/1e9))
}

// ------------------------------------------------- 4. ALU probe
print("\n=== 4. raw 32-bit integer ALU throughput ===")
do {
    let threads = 1 << 20
    let ops = 15  // ops per inner iteration counted conservatively
    let iters = 256
    for _ in 0..<3 {
        let cb = q.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
        e.setComputePipelineState(pAlu); e.setBuffer(bOut,offset:0,index:0); e.setBuffer(bKey,offset:0,index:1)
        e.dispatchThreads(MTLSize(width:threads,height:1,depth:1), threadsPerThreadgroup: MTLSize(width:256,height:1,depth:1))
        e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    }
    let reps = 20
    let t0 = now()
    let cb = q.makeCommandBuffer()!
    for _ in 0..<reps {
        let e = cb.makeComputeCommandEncoder()!
        e.setComputePipelineState(pAlu); e.setBuffer(bOut,offset:0,index:0); e.setBuffer(bKey,offset:0,index:1)
        e.dispatchThreads(MTLSize(width:threads,height:1,depth:1), threadsPerThreadgroup: MTLSize(width:256,height:1,depth:1))
        e.endEncoding()
    }
    cb.commit(); cb.waitUntilCompleted()
    let dt = now()-t0
    let total = Double(threads) * Double(iters) * Double(ops) * Double(reps)
    print(String(format: "  ~%.1f Gop/s of 32-bit integer ops (%.2f s for %.3g ops)", total/dt/1e9, dt, total))
}
print("\ndone")
