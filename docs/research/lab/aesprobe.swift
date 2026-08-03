import Foundation
import Metal
let dev = MTLCreateSystemDefaultDevice()!
print("device: \(dev.name)  unified=\(dev.hasUnifiedMemory)")
let fams: [(String, MTLGPUFamily)] = [("Apple7",.apple7),("Apple8",.apple8),("Apple9",.apple9),
  ("Metal3",.metal3),("Common3",.common3)]
for (n,f) in fams { print("  supportsFamily(\(n)) = \(dev.supportsFamily(f))") }
// probe for any AES / crypto intrinsic or header in MSL
let probes: [(String,String)] = [
 ("#include <metal_crypto>", "#include <metal_stdlib>\n#include <metal_crypto>\nkernel void k(){}"),
 ("metal::aes_encrypt", "#include <metal_stdlib>\nusing namespace metal;\nkernel void k(device uint4*o){o[0]=aes_encrypt(o[1],o[2]);}"),
 ("aese", "#include <metal_stdlib>\nusing namespace metal;\nkernel void k(device uint4*o){o[0]=aese(o[1],o[2]);}"),
 ("__metal_aes_enc", "#include <metal_stdlib>\nusing namespace metal;\nkernel void k(device uint4*o){o[0]=__metal_aes_enc(o[1],o[2]);}"),
 ("clmul / pmull", "#include <metal_stdlib>\nusing namespace metal;\nkernel void k(device uint*o){o[0]=clmul(o[1],o[2]);}"),
 ("polynomial mul", "#include <metal_stdlib>\nusing namespace metal;\nkernel void k(device uint*o){o[0]=carryless_mul(o[1],o[2]);}"),
 ("sha256 intrinsic", "#include <metal_stdlib>\nusing namespace metal;\nkernel void k(device uint4*o){o[0]=sha256su0(o[1],o[2]);}"),
 ("CONTROL: popcount (should PASS)", "#include <metal_stdlib>\nusing namespace metal;\nkernel void k(device uint*o){o[0]=popcount(o[1]);}"),
 ("CONTROL: extract_bits (should PASS)", "#include <metal_stdlib>\nusing namespace metal;\nkernel void k(device uint*o){o[0]=extract_bits(o[1],0,4);}"),
 ("CONTROL: rotate (should PASS)", "#include <metal_stdlib>\nusing namespace metal;\nkernel void k(device uint*o){o[0]=rotate(o[1],7u);}"),
]
for (name, src) in probes {
    do { _ = try dev.makeLibrary(source: src, options: nil); print("  MSL \(name): COMPILES") }
    catch { let m = "\(error)".split(separator: "\n").first(where: {$0.contains("error")}) ?? "err"
            print("  MSL \(name): REJECTED  [\(m.trimmingCharacters(in: .whitespaces).prefix(90))]") }
}
