import Foundation
import Metal

pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0)

let src = """
#include <metal_stdlib>
using namespace metal;
kernel void stamp(device uint *o [[buffer(0)]], constant uint &v [[buffer(1)]],
                  uint g [[thread_position_in_grid]]) { if (g == 0) o[0] = v; }
"""
func die(_ m: String) -> Never { FileHandle.standardError.write((m+"\n").data(using:.utf8)!); exit(1) }
guard let dev = MTLCreateSystemDefaultDevice() else { die("no device") }
let lib = try! dev.makeLibrary(source: src, options: nil)
let pso = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "stamp")!)

guard let q4 = try? dev.makeMTL4CommandQueue() else { die("no MTL4 queue") }
print("MTL4 queue OK on \(dev.name)")
let allocDesc = MTL4CommandAllocatorDescriptor()
guard let alloc = try? dev.makeCommandAllocator(descriptor: allocDesc) else { die("no allocator") }
guard let cb4 = dev.makeCommandBuffer() else { die("no MTL4 cb") }

let atDesc = MTL4ArgumentTableDescriptor()
atDesc.maxBufferBindCount = 4
guard let argTable = try? dev.makeArgumentTable(descriptor: atDesc) else { die("no arg table") }

let bOut = dev.makeBuffer(length: 4096, options: .storageModeShared)!
let bVal = dev.makeBuffer(length: 4096, options: .storageModeShared)!
let flag = bOut.contents().bindMemory(to: UInt32.self, capacity: 8)
let valp = bVal.contents().bindMemory(to: UInt32.self, capacity: 8)
argTable.setAddress(bOut.gpuAddress, index: 0)
argTable.setAddress(bVal.gpuAddress, index: 1)

// residency: make buffers resident for the queue
let rsDesc = MTLResidencySetDescriptor()
let rs = try! dev.makeResidencySet(descriptor: rsDesc)
rs.addAllocation(bOut); rs.addAllocation(bVal); rs.commit(); rs.requestResidency()
q4.addResidencySet(rs)

func now() -> Double { Double(DispatchTime.now().uptimeNanoseconds) * 1e-9 }
func stats(_ s: [Double], _ l: String) {
    let v = s.sorted()
    print(String(format: "  %-36@ min %8.2f  p50 %8.2f  p99 %8.2f us", l as NSString, v[0]*1e6, v[v.count/2]*1e6, v[v.count*99/100]*1e6))
}

var samples = [Double](); var bad = 0
let N = 3000
for i in 0..<(N + 300) {
    let sent = UInt32(i + 1000)
    valp[0] = sent
    flag[0] = 0
    let t0 = now()
    alloc.reset()
    cb4.beginCommandBuffer(allocator: alloc)
    let e = cb4.makeComputeCommandEncoder()!
    e.setArgumentTable(argTable)
    e.setComputePipelineState(pso)
    e.dispatchThreads(threadsPerGrid: MTLSize(width:1,height:1,depth:1), threadsPerThreadgroup: MTLSize(width:1,height:1,depth:1))
    e.endEncoding()
    cb4.endCommandBuffer()
    q4.commit([cb4])
    let ok = poll_u32(UnsafeMutablePointer<UInt32>(flag), sent, 5_000_000)
    let dt = now() - t0
    if i >= 300 { samples.append(dt); if ok == 0 { bad += 1 } }
}
print("MTL4 sentinel mismatches: \(bad)")
stats(samples, "MTL4 commit -> GPU flag visible")
