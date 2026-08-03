#include <metal_stdlib>
using namespace metal;
kernel void k(device uint *o [[buffer(0)]], uint g [[thread_position_in_grid]]) {
    o[g] = clmul(o[g], o[g+1]);
}
