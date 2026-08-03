import Metal
import Foundation
let dev = MTLCreateSystemDefaultDevice()!
let q = dev.makeCommandQueue()!
let src = """
#include <metal_stdlib>
using namespace metal;
#define MASK51 0x7ffffffffffffUL
typedef ulong fe[5];
inline void mac(thread ulong &lo, thread ulong &hi, ulong a, ulong b){
  ulong pl=a*b, ph=mulhi(a,b); ulong nl=lo+pl; hi+=ph+(ulong)(nl<pl); lo=nl; }
inline void carry5(thread ulong* h, thread ulong* lo, thread ulong* hi){
  ulong c;
  c=(hi[0]<<13)|(lo[0]>>51); h[0]=lo[0]&MASK51;
  { ulong n=lo[1]+c; hi[1]+=(ulong)(n<lo[1]); lo[1]=n; }
  c=(hi[1]<<13)|(lo[1]>>51); h[1]=lo[1]&MASK51;
  { ulong n=lo[2]+c; hi[2]+=(ulong)(n<lo[2]); lo[2]=n; }
  c=(hi[2]<<13)|(lo[2]>>51); h[2]=lo[2]&MASK51;
  { ulong n=lo[3]+c; hi[3]+=(ulong)(n<lo[3]); lo[3]=n; }
  c=(hi[3]<<13)|(lo[3]>>51); h[3]=lo[3]&MASK51;
  { ulong n=lo[4]+c; hi[4]+=(ulong)(n<lo[4]); lo[4]=n; }
  c=(hi[4]<<13)|(lo[4]>>51); h[4]=lo[4]&MASK51;
  h[0]+=c*19; h[1]+=h[0]>>51; h[0]&=MASK51; }
inline void fe_mul(thread ulong* h, thread const ulong* a, thread const ulong* b){
  ulong B1=b[1]*19,B2=b[2]*19,B3=b[3]*19,B4=b[4]*19;
  ulong lo[5]={0,0,0,0,0},hi[5]={0,0,0,0,0};
  mac(lo[0],hi[0],a[0],b[0]);mac(lo[0],hi[0],a[1],B4);mac(lo[0],hi[0],a[2],B3);mac(lo[0],hi[0],a[3],B2);mac(lo[0],hi[0],a[4],B1);
  mac(lo[1],hi[1],a[0],b[1]);mac(lo[1],hi[1],a[1],b[0]);mac(lo[1],hi[1],a[2],B4);mac(lo[1],hi[1],a[3],B3);mac(lo[1],hi[1],a[4],B2);
  mac(lo[2],hi[2],a[0],b[2]);mac(lo[2],hi[2],a[1],b[1]);mac(lo[2],hi[2],a[2],b[0]);mac(lo[2],hi[2],a[3],B4);mac(lo[2],hi[2],a[4],B3);
  mac(lo[3],hi[3],a[0],b[3]);mac(lo[3],hi[3],a[1],b[2]);mac(lo[3],hi[3],a[2],b[1]);mac(lo[3],hi[3],a[3],b[0]);mac(lo[3],hi[3],a[4],B4);
  mac(lo[4],hi[4],a[0],b[4]);mac(lo[4],hi[4],a[1],b[3]);mac(lo[4],hi[4],a[2],b[2]);mac(lo[4],hi[4],a[3],b[1]);mac(lo[4],hi[4],a[4],b[0]);
  carry5(h,lo,hi); }
inline void fe_sq(thread ulong* h, thread const ulong* a){
  ulong a0_2=2*a[0],a1_2=2*a[1],a3_19=19*a[3],a4_19=19*a[4];
  ulong lo[5]={0,0,0,0,0},hi[5]={0,0,0,0,0};
  mac(lo[0],hi[0],a[0],a[0]);mac(lo[0],hi[0],a1_2,a4_19);mac(lo[0],hi[0],2*a[2],a3_19);
  mac(lo[1],hi[1],a0_2,a[1]);mac(lo[1],hi[1],2*a[2],a4_19);mac(lo[1],hi[1],a[3],a3_19);
  mac(lo[2],hi[2],a0_2,a[2]);mac(lo[2],hi[2],a[1],a[1]);mac(lo[2],hi[2],2*a[3],a4_19);
  mac(lo[3],hi[3],a0_2,a[3]);mac(lo[3],hi[3],a1_2,a[2]);mac(lo[3],hi[3],a[4],a4_19);
  mac(lo[4],hi[4],a0_2,a[4]);mac(lo[4],hi[4],a1_2,a[3]);mac(lo[4],hi[4],a[2],a[2]);
  carry5(h,lo,hi); }
inline void fe_add(thread ulong* h, thread const ulong* f, thread const ulong* g){
  for(int i=0;i<5;i++) h[i]=f[i]+g[i]; }
inline void fe_sub(thread ulong* h, thread const ulong* f, thread const ulong* g){
  h[0]=(f[0]+0xFFFFFFFFFFFDAUL)-g[0];
  for(int i=1;i<5;i++) h[i]=(f[i]+0xFFFFFFFFFFFFEUL)-g[i]; }
inline void fe_m121666(thread ulong* h, thread const ulong* f){
  ulong lo[5],hi[5];
  for(int i=0;i<5;i++){ lo[i]=f[i]*121666UL; hi[i]=mulhi(f[i],121666UL); }
  carry5(h,lo,hi); }
inline void cswap(thread ulong* a, thread ulong* b, ulong bit){
  ulong m = 0UL - bit;
  for(int i=0;i<5;i++){ ulong t=m&(a[i]^b[i]); a[i]^=t; b[i]^=t; } }

kernel void ladder(device ulong* o [[buffer(0)]], constant uint& reps [[buffer(1)]],
                   uint gid [[thread_position_in_grid]]) {
  ulong acc = 0;
  for (uint r=0; r<reps; ++r) {
    ulong x1[5]={(ulong)(gid+r+9),2,3,4,5};
    ulong x2[5]={1,0,0,0,0}, z2[5]={0,0,0,0,0};
    ulong x3[5]={x1[0],x1[1],x1[2],x1[3],x1[4]}, z3[5]={1,0,0,0,0};
    ulong sc = 0x5A5A5A5A5A5A5A5AUL ^ (ulong)gid;
    ulong swap = 0;
    ulong a[5],b[5],aa[5],bb[5],e[5],c[5],d[5],da[5],cb[5],t[5];
    for (int pos=254; pos>=0; --pos) {
      ulong bit = (sc >> (pos & 63)) & 1;
      swap ^= bit; cswap(x2,x3,swap); cswap(z2,z3,swap); swap = bit;
      fe_add(a,x2,z2); fe_sq(aa,a);
      fe_sub(b,x2,z2); fe_sq(bb,b);
      fe_sub(e,aa,bb);
      fe_add(c,x3,z3); fe_sub(d,x3,z3);
      fe_mul(da,d,a); fe_mul(cb,c,b);
      fe_add(t,da,cb); fe_sq(x3,t);
      fe_sub(t,da,cb); fe_sq(t,t); fe_mul(z3,x1,t);
      fe_mul(x2,aa,bb);
      fe_m121666(t,e); fe_add(t,t,bb); fe_mul(z2,e,t);
    }
    cswap(x2,x3,swap); cswap(z2,z3,swap);
    // inversion: z2^(p-2) approximated by the standard 254-sq/11-mul addition chain cost
    ulong inv[5]={z2[0],z2[1],z2[2],z2[3],z2[4]};
    for(int i=0;i<254;i++){ fe_sq(inv,inv); }
    for(int i=0;i<11;i++){ fe_mul(inv,inv,z2); }
    fe_mul(t,x2,inv);
    acc ^= t[0]^t[1]^t[2]^t[3]^t[4];
  }
  o[gid]=acc;
}
"""
let lib = try dev.makeLibrary(source: src, options: nil)
let p = try dev.makeComputePipelineState(function: lib.makeFunction(name:"ladder")!)
print("ladder maxTotalThreadsPerThreadgroup: \(p.maxTotalThreadsPerThreadgroup) (1024=no spill pressure, low=spilling)")
func run(threads:Int, reps:UInt32)->Double{
  let out=dev.makeBuffer(length:threads*8,options:.storageModePrivate)!
  var r=reps; let rb=dev.makeBuffer(bytes:&r,length:4,options:.storageModeShared)!
  let tg=min(threads,p.maxTotalThreadsPerThreadgroup)
  var best=Double.infinity
  for k in 0..<4{
    let t0=DispatchTime.now().uptimeNanoseconds
    let cb=q.makeCommandBuffer()!;let e=cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(p);e.setBuffer(out,offset:0,index:0);e.setBuffer(rb,offset:0,index:1)
    e.dispatchThreads(MTLSize(width:threads,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:tg,height:1,depth:1))
    e.endEncoding();cb.commit();cb.waitUntilCompleted()
    let dt=Double(DispatchTime.now().uptimeNanoseconds-t0)/1e9
    if k>=1 { best=min(best,dt) }
  }
  return best
}
for th in [8192, 32768, 131072] {
  let reps: UInt32 = 2
  let s = run(threads: th, reps: reps)
  print(String(format:"GPU X25519-shaped ladder: %6d lanes, %.3f s -> %.0f ops/s", th, s, Double(th)*Double(reps)/s))
}
