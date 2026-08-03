import Foundation
import Metal

// Kernel copied verbatim from bench3.swift, plus a keystream-only kernel that
// writes the raw ChaCha20 keystream so we can check it against RFC 8439.
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

// keystream-only: one 64B block per thread, counter = gid. For test vectors.
kernel void ks(device uint4 *out [[buffer(0)]],
               constant uint *key [[buffer(1)]],
               uint gid [[thread_position_in_grid]]) {
    uint x0=0x61707865u,x1=0x3320646eu,x2=0x79622d32u,x3=0x6b206574u;
    uint x4=key[0],x5=key[1],x6=key[2],x7=key[3];
    uint x8=key[4],x9=key[5],x10=key[6],x11=key[7];
    uint x12=gid,x13=key[8],x14=key[9],x15=key[10];
    uint z0=x0,z1=x1,z2=x2,z3=x3,z4=x4,z5=x5,z6=x6,z7=x7;
    uint z8=x8,z9=x9,z10=x10,z11=x11,z12=x12,z13=x13,z14=x14,z15=x15;
    for (int r=0;r<10;++r) {
        QR(x0,x4,x8,x12) QR(x1,x5,x9,x13) QR(x2,x6,x10,x14) QR(x3,x7,x11,x15)
        QR(x0,x5,x10,x15) QR(x1,x6,x11,x12) QR(x2,x7,x8,x13) QR(x3,x4,x9,x14)
    }
    x0+=z0;x1+=z1;x2+=z2;x3+=z3;x4+=z4;x5+=z5;x6+=z6;x7+=z7;
    x8+=z8;x9+=z9;x10+=z10;x11+=z11;x12+=z12;x13+=z13;x14+=z14;x15+=z15;
    out[gid*4+0]=uint4(x0,x1,x2,x3);   out[gid*4+1]=uint4(x4,x5,x6,x7);
    out[gid*4+2]=uint4(x8,x9,x10,x11); out[gid*4+3]=uint4(x12,x13,x14,x15);
}

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
    uint cbase = gid * 16;
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
let pNop = pipe("nop"), pAead = pipe("chacha20poly1305"), pKs = pipe("ks")
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

// ---------- 1. CORRECTNESS: RFC 8439 §2.3.2 test vector ----------
// key = 00..1f, nonce = 00:00:00:09 00:00:00:4a 00:00:00:00, counter = 1
func correctness() {
    let k = bK.contents().bindMemory(to: UInt32.self, capacity: 16)
    for i in 0..<8 {
        // key bytes 00 01 02 ... 1f, little-endian words
        let b0 = UInt32(i*4), b1 = UInt32(i*4+1), b2 = UInt32(i*4+2), b3 = UInt32(i*4+3)
        k[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }
    k[8]  = 0x09000000
    k[9]  = 0x4a000000
    k[10] = 0x00000000
    // counter is gid; we want counter==1 so read block gid=1
    let cb = q.makeCommandBuffer()!
    dispatch(cb, pKs, 2)
    cb.commit(); cb.waitUntilCompleted()
    let o = bOut.contents().bindMemory(to: UInt32.self, capacity: 32)
    // RFC 8439 2.3.2 expected keystream for counter 1
    let expect: [UInt32] = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
    ]
    var ok = true
    for i in 0..<16 where o[16+i] != expect[i] { ok = false }
    print("1. RFC 8439 2.3.2 keystream (counter=1): \(ok ? "PASS - kernel is a real ChaCha20" : "FAIL")")
    if !ok {
        print("   got:    " + (0..<16).map { String(format:"%08x", o[16+$0]) }.joined(separator:" "))
        print("   expect: " + expect.map { String(format:"%08x", $0) }.joined(separator:" "))
    }
    memset(bK.contents(), 0x37, 4096)
}

// ---------- 2. HONEST SINGLE-DISPATCH THROUGHPUT ----------
// What a synchronous seal() API actually costs: one command buffer, one
// dispatch, commit, wait. NOT amortised over thousands of queued dispatches.
func singleShot() {
    print("\n2. Single-dispatch (what a synchronous seal() API costs)")
    print("   size     amortised(bench3 method)   single-shot   GPU-busy   overhead")
    for s in [1<<20, 4<<20, 16<<20, 64<<20] {
        let threads = s/1024
        for _ in 0..<5 { let cb = q.makeCommandBuffer()!; dispatch(cb,pAead,threads); cb.commit(); cb.waitUntilCompleted() }

        // amortised: many dispatches in ONE command buffer (bench3's method)
        let iters = max(1, min(2000, Int(0.3 / (Double(s)/4e10))))
        var t0 = now()
        let cbA = q.makeCommandBuffer()!
        for _ in 0..<iters { dispatch(cbA,pAead,threads) }
        cbA.commit(); cbA.waitUntilCompleted()
        let amort = Double(s*iters)/(now()-t0)/1e9

        // single-shot: commit+wait each time, like a blocking API call
        var reps = max(20, min(400, Int(0.3 / (Double(s)/4e10))))
        var gpuBusy = 0.0
        t0 = now()
        for _ in 0..<reps {
            let cb = q.makeCommandBuffer()!
            dispatch(cb,pAead,threads)
            cb.commit(); cb.waitUntilCompleted()
            gpuBusy += cb.gpuEndTime - cb.gpuStartTime
        }
        let wall = now()-t0
        let single = Double(s*reps)/wall/1e9
        let ovh = (wall - gpuBusy)/Double(reps)*1e6
        print(String(format: "   %5d KiB  %8.2f GB/s          %8.2f GB/s  %5.1f%%   %6.1f us/call",
                     s>>10, amort, single, gpuBusy/wall*100, ovh))
        _ = reps
    }
}

// ---------- 3. CONTENTION: GPU while the CPU is busy ----------
// The claimed winning regime requires the CPU to be simultaneously busy.
// GPU and CPU share one LPDDR memory controller on M4.
func contention() {
    print("\n3. Contention - GPU AEAD alone vs with 10 CPU threads streaming memory")
    let s = 16 << 20, threads = s/1024
    func gpuRate(_ secs: Double) -> Double {
        for _ in 0..<3 { let cb = q.makeCommandBuffer()!; dispatch(cb,pAead,threads); cb.commit(); cb.waitUntilCompleted() }
        let t0 = now(); var total = 0.0
        while now()-t0 < secs {
            let cb = q.makeCommandBuffer()!
            for _ in 0..<8 { dispatch(cb,pAead,threads) }
            cb.commit(); cb.waitUntilCompleted()
            total += Double(s*8)
        }
        return total/(now()-t0)/1e9
    }
    let quiet = gpuRate(2.0)

    // spin up 10 CPU threads doing memory-heavy work (stand-in for AES-GCM)
    let stop = UnsafeMutablePointer<Int32>.allocate(capacity: 1); stop.pointee = 0
    let cpuBytes = UnsafeMutablePointer<Int64>.allocate(capacity: 1); cpuBytes.pointee = 0
    let lock = NSLock()
    var ts: [Thread] = []
    for _ in 0..<10 {
        let t = Thread {
            let n = 8 << 20
            let a = UnsafeMutablePointer<UInt64>.allocate(capacity: n/8)
            memset(a, 0x11, n)
            var local: Int64 = 0
            while stop.pointee == 0 {
                var acc: UInt64 = 0
                for i in 0..<(n/8) { acc ^= a[i]; a[i] = acc &* 0x9E3779B97F4A7C15 }
                local += Int64(n)*2
                if acc == 0xdeadbeef { print("") }
            }
            lock.lock(); cpuBytes.pointee += local; lock.unlock()
            a.deallocate()
        }
        t.stackSize = 1 << 20
        ts.append(t); t.start()
    }
    Thread.sleep(forTimeInterval: 0.5)
    let tCpu0 = now()
    let busy = gpuRate(3.0)
    let cpuWindow = now()-tCpu0
    stop.pointee = 1
    Thread.sleep(forTimeInterval: 0.4)
    print(String(format: "   GPU AEAD, CPU idle : %6.2f GB/s", quiet))
    print(String(format: "   GPU AEAD, CPU busy : %6.2f GB/s   (%.0f%% of quiet)", busy, busy/quiet*100))
    print(String(format: "   CPU mem traffic during that window: ~%.1f GB/s", Double(cpuBytes.pointee)/cpuWindow/1e9))
}

correctness()
singleShot()
contention()
