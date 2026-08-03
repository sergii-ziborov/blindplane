import Metal
import Foundation

guard let dev = MTLCreateSystemDefaultDevice() else { print("NO DEVICE"); exit(1) }
print("device: \(dev.name)")
print("unifiedMemory: \(dev.hasUnifiedMemory)")
print("maxThreadsPerThreadgroup: \(dev.maxThreadsPerThreadgroup)")
if #available(macOS 13.0, *) { print("supportsFamily(.apple9): \(dev.supportsFamily(.apple9))") }

// Probe 1: does MSL have 64-bit integers and a 64x64->high-half multiply?
let probes: [(String, String)] = [
  ("ulong basic", """
   #include <metal_stdlib>
   using namespace metal;
   kernel void k(device ulong* o [[buffer(0)]], uint i [[thread_position_in_grid]]) {
     ulong a = o[i]; ulong b = a * 6364136223846793005UL; o[i] = b;
   }
   """),
  ("mulhi(ulong,ulong) 64x64 high half", """
   #include <metal_stdlib>
   using namespace metal;
   kernel void k(device ulong* o [[buffer(0)]], uint i [[thread_position_in_grid]]) {
     o[i] = mulhi(o[i], (ulong)6364136223846793005UL);
   }
   """),
  ("__int128", """
   #include <metal_stdlib>
   using namespace metal;
   kernel void k(device ulong* o [[buffer(0)]], uint i [[thread_position_in_grid]]) {
     __uint128_t a = (__uint128_t)o[i] * (__uint128_t)o[i+1];
     o[i] = (ulong)(a >> 64);
   }
   """),
  ("addcarry / carry flag intrinsic", """
   #include <metal_stdlib>
   using namespace metal;
   kernel void k(device uint* o [[buffer(0)]], uint i [[thread_position_in_grid]]) {
     uint c; o[i] = addc(o[i], o[i+1], c);
   }
   """),
  ("mulhi(uint,uint) 32x32 high half", """
   #include <metal_stdlib>
   using namespace metal;
   kernel void k(device uint* o [[buffer(0)]], uint i [[thread_position_in_grid]]) {
     o[i] = mulhi(o[i], o[i+1]);
   }
   """),
]
for (name, src) in probes {
  do { _ = try dev.makeLibrary(source: src, options: nil); print("PROBE OK      : \(name)") }
  catch { let m = "\(error)".split(separator: "\n").filter{ $0.contains("error") }.first ?? "?"
          print("PROBE FAIL    : \(name) -> \(m)") }
}
