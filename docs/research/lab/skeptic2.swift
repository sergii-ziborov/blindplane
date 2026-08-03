import Foundation
import Metal

// Validate the "poll a GPU-written flag in shared memory" round trip:
// the kernel writes a per-iteration sentinel, and the host checks it matches.
let src = """
#include <metal_stdlib>
using namespace metal;
kernel void stamp(device uint *o [[buffer(0)]], constant uint &v [[buffer(1)]],
                  uint g [[thread_position_in_grid]]) { if (g == 0) o[0] = v; }
// realistic per-record work: ChaCha20 keystream over 4 KiB (64 blocks), one thread per block
#define ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define QR(a,b,c,d) a+=b; d^=a; d=ROTL(d,16); c+=d; b^=c; b=ROTL(b,12); a+=b; d^=a; d=ROTL(d,8); c+=d; b^=c; b=ROTL(b,7);
kernel void seal4k(device uint4 *out [[buffer(0)]], constant uint *k [[buffer(1)]],
                   device const uint4 *inp [[buffer(2)]], device atomic_uint *doneflag [[buffer(3)]],
                   constant uint &sentinel [[buffer(4)]], uint g [[thread_position_in_grid]]) {
    uint x0=0x61707865u,x1=0x3320646eu,x2=0x79622d32u,x3=0x6b206574u;
    uint x4=k[0],x5=k[1],x6=k[2],x7=k[3],x8=k[4],x9=k[5],x10=k[6],x11=k[7];
    uint x12=g,x13=k[8],x14=k[9],x15=k[10];
    uint z0=x0,z1=x1,z2=x2,z3=x3,z4=x4,z5=x5,z6=x6,z7=x7,z8=x8,z9=x9,z10=x10,z11=x11,z12=x12,z13=x13,z14=x14,z15=x15;
    for (int r=0;r<10;++r){ QR(x0,x4,x8,x12) QR(x1,x5,x9,x13) QR(x2,x6,x10,x14) QR(x3,x7,x11,x15)
                            QR(x0,x5,x10,x15) QR(x1,x6,x11,x12) QR(x2,x7,x8,x13) QR(x3,x4,x9,x14) }
    x0+=z0;x1+=z1;x2+=z2;x3+=z3;x4+=z4;x5+=z5;x6+=z6;x7+=z7;x8+=z8;x9+=z9;x10+=z10;x11+=z11;x12+=z12;x13+=z13;x14+=z14;x15+=z15;
    out[g*4+0]=inp[g*4+0]^uint4(x0,x1,x2,x3);
    out[g*4+1]=inp[g*4+1]^uint4(x4,x5,x6,x7);
    out[g*4+2]=inp[g*4+2]^uint4(x8,x9,x10,x11);
    out[g*4+3]=inp[g*4+3]^uint4(x12,x13,x14,x15);
    threadgroup_barrier(mem_flags::mem_device);
    if (g == 0) atomic_store_explicit(doneflag, sentinel, memory_order_relaxed);
}
"""
func die(_ m: String) -> Never { FileHandle.standardError.write((m+"\n").data(using:.utf8)!); exit(1) }
guard let dev = MTLCreateSystemDefaultDevice(), let q = dev.makeCommandQueue(maxCommandBufferCount: 64) else { die("no metal") }
let lib = try! dev.makeLibrary(source: src, options: nil)
let pStamp = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "stamp")!)
let pSeal  = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "seal4k")!)
let bFlag = dev.makeBuffer(length: 4096, options: .storageModeShared)!
let bOut  = dev.makeBuffer(length: 1<<20, options: .storageModeShared)!
let bIn   = dev.makeBuffer(length: 1<<20, options: .storageModeShared)!
let bKey  = dev.makeBuffer(length: 4096, options: .storageModeShared)!
memset(bIn.contents(), 0x5a, 1<<20); memset(bKey.contents(), 0x37, 4096)
func now() -> Double { Double(DispatchTime.now().uptimeNanoseconds) * 1e-9 }
func stats(_ s: [Double], _ l: String) {
    let v = s.sorted()
    print(String(format: "  %-40@ min %8.2f  p50 %8.2f  p99 %8.2f us", l as NSString, v[0]*1e6, v[v.count/2]*1e6, v[v.count*99/100]*1e6))
}
let flag = bFlag.contents().bindMemory(to: UInt32.self, capacity: 8)

// --- validated stamp round trip
flag[0] = 0
var bad = 0, s1 = [Double]()
for _ in 0..<300 { let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
  e.setComputePipelineState(pStamp); e.setBuffer(bFlag,offset:0,index:0); var v:UInt32=1; e.setBytes(&v,length:4,index:1)
  e.dispatchThreads(MTLSize(width:1,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:1,height:1,depth:1)); e.endEncoding()
  cb.commit(); cb.waitUntilCompleted() }
for i in 0..<3000 {
    var sent = UInt32(i + 1000)
    flag[0] = 0
    let t0 = now()
    let cb = q.makeCommandBuffer()!
    let e = cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(pStamp); e.setBuffer(bFlag, offset:0, index:0); e.setBytes(&sent, length:4, index:1)
    e.dispatchThreads(MTLSize(width:1,height:1,depth:1), threadsPerThreadgroup: MTLSize(width:1,height:1,depth:1))
    e.endEncoding(); cb.commit()
    var spin = 0
    while flag[0] != sent { spin += 1; if spin > 200_000_000 { break } }
    s1.append(now()-t0)
    if flag[0] != sent { bad += 1 }
    cb.waitUntilCompleted()
}
print("validated sentinel mismatches: \(bad)")
stats(s1, "empty-ish kernel, poll GPU sentinel")

// --- real 4 KiB ChaCha20 seal, polled the same way
var s2 = [Double](); var bad2 = 0
let threads = 64
for i in 0..<2000 {
    var sent = UInt32(i + 7)
    flag[0] = 0
    let t0 = now()
    let cb = q.makeCommandBuffer()!
    let e = cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(pSeal)
    e.setBuffer(bOut,offset:0,index:0); e.setBuffer(bKey,offset:0,index:1)
    e.setBuffer(bIn,offset:0,index:2); e.setBuffer(bFlag,offset:0,index:3); e.setBytes(&sent,length:4,index:4)
    e.dispatchThreads(MTLSize(width:threads,height:1,depth:1), threadsPerThreadgroup: MTLSize(width:threads,height:1,depth:1))
    e.endEncoding(); cb.commit()
    var spin = 0
    while flag[0] != sent { spin += 1; if spin > 200_000_000 { break } }
    s2.append(now()-t0)
    if flag[0] != sent { bad2 += 1 }
    cb.waitUntilCompleted()
}
print("4KiB seal sentinel mismatches: \(bad2)")
stats(s2, "4 KiB ChaCha20 on GPU, poll sentinel")
