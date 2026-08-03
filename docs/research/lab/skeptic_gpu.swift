import Foundation
import Metal

let src = """
#include <metal_stdlib>
using namespace metal;
kernel void nop(device uint *o [[buffer(0)]], uint g [[thread_position_in_grid]]) {}
kernel void touch(device uint *o [[buffer(0)]], uint g [[thread_position_in_grid]]) { if (g==0) o[0] += 1; }
"""

func die(_ m: String) -> Never { FileHandle.standardError.write((m+"\n").data(using:.utf8)!); exit(1) }
guard let dev = MTLCreateSystemDefaultDevice(), let q = dev.makeCommandQueue(maxCommandBufferCount: 64) else { die("no metal") }
let lib = try! dev.makeLibrary(source: src, options: nil)
let pNop = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "nop")!)
let pTouch = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "touch")!)
let bOut = dev.makeBuffer(length: 1 << 20, options: .storageModeShared)!
func now() -> Double { Double(DispatchTime.now().uptimeNanoseconds) * 1e-9 }

func encode(_ cb: MTLCommandBuffer, _ p: MTLComputePipelineState, _ threads: Int) {
    let e = cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(p)
    e.setBuffer(bOut, offset: 0, index: 0)
    e.dispatchThreads(MTLSize(width: threads, height: 1, depth: 1),
                      threadsPerThreadgroup: MTLSize(width: min(threads, 64), height: 1, depth: 1))
    e.endEncoding()
}
func stats(_ s: [Double], _ label: String) {
    let v = s.sorted()
    print(String(format: "  %-42@ min %7.2f  p50 %7.2f  p99 %7.2f us", label as NSString,
                 v[0]*1e6, v[v.count/2]*1e6, v[v.count*99/100]*1e6))
}

print("device \(dev.name)")

// warm up
for _ in 0..<200 { let cb = q.makeCommandBuffer()!; encode(cb, pNop, 1); cb.commit(); cb.waitUntilCompleted() }

let N = 3000

// A. blocking waitUntilCompleted
var a = [Double]()
for _ in 0..<N {
    let t0 = now(); let cb = q.makeCommandBuffer()!; encode(cb, pNop, 1); cb.commit(); cb.waitUntilCompleted(); a.append(now()-t0)
}
stats(a, "A blocking waitUntilCompleted")

// B. busy-poll on cb.status (no thread sleep/wakeup)
var b = [Double]()
for _ in 0..<N {
    let t0 = now(); let cb = q.makeCommandBuffer()!; encode(cb, pNop, 1); cb.commit()
    while cb.status != .completed && cb.status != .error { }
    b.append(now()-t0)
}
stats(b, "B busy-poll cb.status")

// C. busy-poll on a shared-memory flag written by the GPU (skips completion bookkeeping)
var c = [Double]()
let flag = bOut.contents().bindMemory(to: UInt32.self, capacity: 4)
for _ in 0..<N {
    flag[0] = 0
    let t0 = now(); let cb = q.makeCommandBuffer()!; encode(cb, pTouch, 1); cb.commit()
    while flag[0] == 0 { }
    c.append(now()-t0)
    cb.waitUntilCompleted()
}
stats(c, "C busy-poll GPU-written flag in shared mem")

// D. GPU timestamps
var wall = [Double](), gwin = [Double](), sched = [Double](), tail = [Double]()
for _ in 0..<N {
    let t0 = now(); let cb = q.makeCommandBuffer()!; encode(cb, pNop, 1); cb.commit(); cb.waitUntilCompleted()
    let t1 = now()
    wall.append(t1-t0); gwin.append(cb.gpuEndTime - cb.gpuStartTime)
    sched.append(max(0, cb.gpuStartTime - cb.kernelStartTime))
    tail.append(max(0, cb.kernelEndTime - cb.gpuEndTime))
}
stats(wall, "D wall"); stats(gwin, "D gpuStart->gpuEnd"); stats(sched, "D kernelStart->gpuStart"); stats(tail, "D gpuEnd->kernelEnd")

// E. PIPELINED: K command buffers in flight, measure amortized per-dispatch cost
for K in [1, 2, 4, 8, 16, 32] {
    let iters = 2000
    var inflight = [MTLCommandBuffer]()
    let t0 = now()
    var done = 0
    var issued = 0
    while done < iters {
        while inflight.count < K && issued < iters {
            let cb = q.makeCommandBuffer()!; encode(cb, pNop, 1); cb.commit(); inflight.append(cb); issued += 1
        }
        let cb = inflight.removeFirst(); cb.waitUntilCompleted(); done += 1
    }
    let dt = now()-t0
    print(String(format: "  E pipelined K=%2d : %7.2f us/dispatch  (%8.0f dispatches/s)", K, dt/Double(iters)*1e6, Double(iters)/dt))
}

// F. many encoders inside ONE command buffer (amortized encode cost, no per-dispatch submit)
for M in [1, 8, 64, 512] {
    let reps = 200
    let t0 = now()
    for _ in 0..<reps {
        let cb = q.makeCommandBuffer()!
        for _ in 0..<M { encode(cb, pNop, 1) }
        cb.commit(); cb.waitUntilCompleted()
    }
    let dt = now()-t0
    print(String(format: "  F %4d encoders/cb : %7.2f us/cb  -> %6.2f us/encoder", M, dt/Double(reps)*1e6, dt/Double(reps*M)*1e6))
}
