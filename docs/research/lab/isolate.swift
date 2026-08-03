import Metal
import Foundation
let dev = MTLCreateSystemDefaultDevice()!
let cases: [(String,String)] = [
 ("nop", "kernel void k(device uint* o [[buffer(0)]], uint i [[thread_position_in_grid]]){o[0]=i;}"),
 ("mullo64", "kernel void k(device ulong* o [[buffer(0)]], uint i [[thread_position_in_grid]]){o[i]=o[i]*0x9E3779B97F4A7C15UL;}"),
 ("mulhi64", "kernel void k(device ulong* o [[buffer(0)]], uint i [[thread_position_in_grid]]){o[i]=mulhi(o[i],(ulong)0x9E3779B97F4A7C15UL);}"),
 ("u128_mul", "kernel void k(device ulong* o [[buffer(0)]], uint i [[thread_position_in_grid]]){__uint128_t p=(__uint128_t)o[i]*(__uint128_t)o[i+1];o[i]=(ulong)(p>>64);}"),
 ("mulhi32", "kernel void k(device uint* o [[buffer(0)]], uint i [[thread_position_in_grid]]){o[i]=mulhi(o[i],o[i+1]);}"),
]
for (n,s) in cases {
  print("--- \(n) ---"); fflush(stdout)
  do {
    let lib = try dev.makeLibrary(source: "#include <metal_stdlib>\nusing namespace metal;\n"+s, options: nil)
    print("  frontend: OK"); fflush(stdout)
    _ = try dev.makeComputePipelineState(function: lib.makeFunction(name:"k")!)
    print("  backend : OK"); fflush(stdout)
  } catch { print("  ERROR: \(error)"); fflush(stdout) }
}
