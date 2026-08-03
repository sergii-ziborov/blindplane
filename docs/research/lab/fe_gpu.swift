import Metal
import Foundation
let dev = MTLCreateSystemDefaultDevice()!
let q = dev.makeCommandQueue()!
let src = """
#include <metal_stdlib>
using namespace metal;
#define MASK51 0x7ffffffffffffUL

inline void mac(thread ulong &lo, thread ulong &hi, ulong a, ulong b) {
  ulong pl = a * b;
  ulong ph = mulhi(a, b);
  ulong nl = lo + pl;
  hi += ph + (ulong)(nl < pl);
  lo = nl;
}
inline void carry5(thread ulong* h, thread ulong* lo, thread ulong* hi) {
  ulong c;
  c = (hi[0] << 13) | (lo[0] >> 51); h[0] = lo[0] & MASK51;
  { ulong n = lo[1] + c; hi[1] += (ulong)(n < lo[1]); lo[1] = n; }
  c = (hi[1] << 13) | (lo[1] >> 51); h[1] = lo[1] & MASK51;
  { ulong n = lo[2] + c; hi[2] += (ulong)(n < lo[2]); lo[2] = n; }
  c = (hi[2] << 13) | (lo[2] >> 51); h[2] = lo[2] & MASK51;
  { ulong n = lo[3] + c; hi[3] += (ulong)(n < lo[3]); lo[3] = n; }
  c = (hi[3] << 13) | (lo[3] >> 51); h[3] = lo[3] & MASK51;
  { ulong n = lo[4] + c; hi[4] += (ulong)(n < lo[4]); lo[4] = n; }
  c = (hi[4] << 13) | (lo[4] >> 51); h[4] = lo[4] & MASK51;
  h[0] += c * 19;
  h[1] += h[0] >> 51; h[0] &= MASK51;
}
inline void fe_mul(thread ulong* h, thread const ulong* a, thread const ulong* b) {
  ulong b1_19=b[1]*19, b2_19=b[2]*19, b3_19=b[3]*19, b4_19=b[4]*19;
  ulong lo[5]={0,0,0,0,0}, hi[5]={0,0,0,0,0};
  mac(lo[0],hi[0],a[0],b[0]); mac(lo[0],hi[0],a[1],b4_19); mac(lo[0],hi[0],a[2],b3_19); mac(lo[0],hi[0],a[3],b2_19); mac(lo[0],hi[0],a[4],b1_19);
  mac(lo[1],hi[1],a[0],b[1]); mac(lo[1],hi[1],a[1],b[0]);  mac(lo[1],hi[1],a[2],b4_19); mac(lo[1],hi[1],a[3],b3_19); mac(lo[1],hi[1],a[4],b2_19);
  mac(lo[2],hi[2],a[0],b[2]); mac(lo[2],hi[2],a[1],b[1]);  mac(lo[2],hi[2],a[2],b[0]);  mac(lo[2],hi[2],a[3],b4_19); mac(lo[2],hi[2],a[4],b3_19);
  mac(lo[3],hi[3],a[0],b[3]); mac(lo[3],hi[3],a[1],b[2]);  mac(lo[3],hi[3],a[2],b[1]);  mac(lo[3],hi[3],a[3],b[0]);  mac(lo[3],hi[3],a[4],b4_19);
  mac(lo[4],hi[4],a[0],b[4]); mac(lo[4],hi[4],a[1],b[3]);  mac(lo[4],hi[4],a[2],b[2]);  mac(lo[4],hi[4],a[3],b[1]);  mac(lo[4],hi[4],a[4],b[0]);
  carry5(h, lo, hi);
}
kernel void fekern(device ulong* o [[buffer(0)]], constant uint& iters [[buffer(1)]],
                   uint gid [[thread_position_in_grid]]) {
  ulong x[5] = { (ulong)gid+1, 2, 3, 4, 5 };
  ulong k[5] = { 0x1234567891234UL, 0x2345678912345UL, 0x3456789123456UL, 0x4567891234567UL, 0x5678912345678UL };
  ulong t[5];
  for (uint i=0;i<iters;++i) { fe_mul(t,x,k); x[0]=t[0];x[1]=t[1];x[2]=t[2];x[3]=t[3];x[4]=t[4]; }
  o[gid] = x[0]^x[1]^x[2]^x[3]^x[4];
}
"""
let lib = try dev.makeLibrary(source: src, options: nil)
let p = try dev.makeComputePipelineState(function: lib.makeFunction(name:"fekern")!)
print("maxTotalThreadsPerThreadgroup: \(p.maxTotalThreadsPerThreadgroup)  (a low number here = register pressure)")
print("threadExecutionWidth: \(p.threadExecutionWidth)")

// correctness check: 4 lanes, 1 iteration, compare against CPU below via printout
let chk = dev.makeBuffer(length: 8*8, options: .storageModeShared)!
var one: UInt32 = 1
let ob = dev.makeBuffer(bytes:&one,length:4,options:.storageModeShared)!
do { let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
  e.setComputePipelineState(p); e.setBuffer(chk,offset:0,index:0); e.setBuffer(ob,offset:0,index:1)
  e.dispatchThreads(MTLSize(width:4,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:4,height:1,depth:1))
  e.endEncoding(); cb.commit(); cb.waitUntilCompleted() }
let cp = chk.contents().bindMemory(to: UInt64.self, capacity: 4)
print(String(format:"gpu fe_mul checksum lane0..3: %016llx %016llx %016llx %016llx", cp[0],cp[1],cp[2],cp[3]))

func run(threads: Int, iters: UInt32) -> Double {
  let out = dev.makeBuffer(length: threads*8, options: .storageModePrivate)!
  var it = iters; let ib = dev.makeBuffer(bytes:&it,length:4,options:.storageModeShared)!
  let tg = min(threads, p.maxTotalThreadsPerThreadgroup)
  var best = Double.infinity
  for r in 0..<6 {
    let t0 = DispatchTime.now().uptimeNanoseconds
    let cb=q.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(p); e.setBuffer(out,offset:0,index:0); e.setBuffer(ib,offset:0,index:1)
    e.dispatchThreads(MTLSize(width:threads,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:tg,height:1,depth:1))
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    let dt = Double(DispatchTime.now().uptimeNanoseconds - t0)/1e9
    if r >= 2 { best = min(best, dt) }
  }
  return best
}
for th in [16384, 65536, 262144] {
  let iters: UInt32 = 20000
  let s = run(threads: th, iters: iters)
  let ops = Double(th)*Double(iters)
  print(String(format:"GPU fe_mul: %7d lanes, %.3f s -> %.2f M fe_mul/s", th, s, ops/s/1e6))
}
