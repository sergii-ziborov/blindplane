import Metal
import Foundation

let dev = MTLCreateSystemDefaultDevice()!
let q = dev.makeCommandQueue()!

let src = """
#include <metal_stdlib>
using namespace metal;

// correctness: 64x64 -> 128 via mulhi/mullo (NOT __uint128_t, which crashes AGX)
kernel void verify(device ulong* o [[buffer(0)]], uint i [[thread_position_in_grid]]) {
  ulong a = 0xDEADBEEFCAFEBABEUL + i;
  ulong b = 0x0123456789ABCDEFUL;
  o[2*i]   = a * b;
  o[2*i+1] = mulhi(a, b);
}

kernel void nop(device uint* o [[buffer(0)]], uint i [[thread_position_in_grid]]) { o[0] = 1; }

// throughput: independent 64x64->128 MACs, 8 accumulators
kernel void mul64(device ulong* o [[buffer(0)]],
                  constant uint& iters [[buffer(1)]],
                  uint gid [[thread_position_in_grid]]) {
  ulong a0=gid+1, a1=gid+3, a2=gid+5, a3=gid+7;
  ulong b0=0x9E3779B97F4A7C15UL, b1=0xC2B2AE3D27D4EB4FUL;
  ulong s0=0,s1=0,s2=0,s3=0;
  for (uint t=0; t<iters; ++t) {
    s0 += mulhi(a0,b0); a0 = a0*b1+1;
    s1 += mulhi(a1,b0); a1 = a1*b1+1;
    s2 += mulhi(a2,b0); a2 = a2*b1+1;
    s3 += mulhi(a3,b0); a3 = a3*b1+1;
  }
  o[gid] = s0^s1^s2^s3;
}

// same shape but 32-bit, to show the native width
kernel void mul32(device uint* o [[buffer(0)]],
                  constant uint& iters [[buffer(1)]],
                  uint gid [[thread_position_in_grid]]) {
  uint a0=gid+1,a1=gid+3,a2=gid+5,a3=gid+7;
  uint b0=0x9E3779B9u, b1=0x27D4EB4Fu;
  uint s0=0,s1=0,s2=0,s3=0;
  for (uint t=0;t<iters;++t){
    s0 += mulhi(a0,b0); a0=a0*b1+1;
    s1 += mulhi(a1,b0); a1=a1*b1+1;
    s2 += mulhi(a2,b0); a2=a2*b1+1;
    s3 += mulhi(a3,b0); a3=a3*b1+1;
  }
  o[gid]=s0^s1^s2^s3;
}
"""
let lib = try dev.makeLibrary(source: src, options: nil)
func pipe(_ n: String) throws -> MTLComputePipelineState {
  try dev.makeComputePipelineState(function: lib.makeFunction(name: n)!)
}
let pVerify = try pipe("verify"), pNop = try pipe("nop")
let pMul64 = try pipe("mul64"), pMul32 = try pipe("mul32")

// ---- correctness of __uint128_t on GPU ----
let vbuf = dev.makeBuffer(length: 16*4, options: .storageModeShared)!
do {
  let cb = q.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
  e.setComputePipelineState(pVerify); e.setBuffer(vbuf, offset: 0, index: 0)
  e.dispatchThreads(MTLSize(width:4,height:1,depth:1), threadsPerThreadgroup: MTLSize(width:4,height:1,depth:1))
  e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
}
let vp = vbuf.contents().bindMemory(to: UInt64.self, capacity: 8)
for i in 0..<2 {
  let a = UInt64(0xDEADBEEFCAFEBABE) &+ UInt64(i), b = UInt64(0x0123456789ABCDEF)
  let (hi, lo) = a.multipliedFullWidth(by: b)
  let ok = (vp[2*i] == lo && vp[2*i+1] == hi)
  print(String(format: "verify[%d] gpu lo=%016llx hi=%016llx  cpu lo=%016llx hi=%016llx  %@",
        i, vp[2*i], vp[2*i+1], lo, hi, ok ? "MATCH" : "MISMATCH"))
}

// ---- dispatch round-trip latency ----
let nbuf = dev.makeBuffer(length: 64, options: .storageModeShared)!
func roundTrip() {
  let cb = q.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
  e.setComputePipelineState(pNop); e.setBuffer(nbuf, offset:0, index:0)
  e.dispatchThreads(MTLSize(width:1,height:1,depth:1), threadsPerThreadgroup: MTLSize(width:1,height:1,depth:1))
  e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
}
for _ in 0..<200 { roundTrip() }   // warm
var samples: [Double] = []
for _ in 0..<500 {
  let t0 = DispatchTime.now().uptimeNanoseconds
  roundTrip()
  samples.append(Double(DispatchTime.now().uptimeNanoseconds - t0) / 1000.0)
}
samples.sort()
print(String(format: "dispatch round-trip us: min=%.1f p50=%.1f p90=%.1f p99=%.1f",
      samples[0], samples[250], samples[450], samples[495]))

// ---- 64-bit and 32-bit multiply throughput ----
func throughput(_ p: MTLComputePipelineState, threads: Int, iters: UInt32, mulsPerIter: Double, label: String) {
  let out = dev.makeBuffer(length: threads*8, options: .storageModePrivate)!
  var it = iters
  let ib = dev.makeBuffer(bytes: &it, length: 4, options: .storageModeShared)!
  // warm
  for _ in 0..<3 {
    let cb = q.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(p); e.setBuffer(out,offset:0,index:0); e.setBuffer(ib,offset:0,index:1)
    e.dispatchThreads(MTLSize(width:threads,height:1,depth:1),
                      threadsPerThreadgroup: MTLSize(width:min(threads,p.maxTotalThreadsPerThreadgroup),height:1,depth:1))
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
  }
  var best = Double.infinity
  for _ in 0..<5 {
    let t0 = DispatchTime.now().uptimeNanoseconds
    let cb = q.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(p); e.setBuffer(out,offset:0,index:0); e.setBuffer(ib,offset:0,index:1)
    e.dispatchThreads(MTLSize(width:threads,height:1,depth:1),
                      threadsPerThreadgroup: MTLSize(width:min(threads,p.maxTotalThreadsPerThreadgroup),height:1,depth:1))
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    best = min(best, Double(DispatchTime.now().uptimeNanoseconds - t0)/1e9)
  }
  let muls = Double(threads) * Double(iters) * mulsPerIter
  print(String(format: "%@: %.3f s, %.2f G multiplies/s (occupancy %d threads)", label, best, muls/best/1e9, threads))
}
// mul64: per iter 4 mulhi + 4 mullo = 8 "64x64" multiply instructions
throughput(pMul64, threads: 262144, iters: 2000, mulsPerIter: 8, label: "GPU 64x64 mul")
// mul32: per iter 4 mulhi + 4 mullo = 8 32x32 multiplies
throughput(pMul32, threads: 262144, iters: 2000, mulsPerIter: 8, label: "GPU 32x32 mul")
