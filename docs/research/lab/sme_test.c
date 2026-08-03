#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/sysctl.h>

// SMOPA (integer widening outer product accumulate) test.
// smopa za0.s, p0/m, p1/m, z0.b, z1.b  -> i8 x i8 -> i32 accumulate
__attribute__((target("sme,sme2")))
__arm_new("za") __arm_locally_streaming
static void sme_smopa_test(const int8_t *a, const int8_t *b, int32_t *out, int svl_bytes) {
    __asm__ volatile(
        "zero {za}\n"
        "ptrue p0.b\n"
        "ptrue p1.b\n"
        "ld1b {z0.b}, p0/z, [%0]\n"
        "ld1b {z1.b}, p1/z, [%1]\n"
        "smopa za0.s, p0/m, p1/m, z0.b, z1.b\n"
        "mov w12, #0\n"
        "st1w {za0h.s[w12, 0]}, p0, [%2]\n"
        :
        : "r"(a), "r"(b), "r"(out)
        : "memory", "z0", "z1", "p0", "p1", "w12", "za"
    );
}

int main(void) {
    int8_t a[256], b[256];
    int32_t out[256];
    memset(out, 0, sizeof(out));
    for (int i = 0; i < 256; i++) { a[i] = (int8_t)(i % 7 + 1); b[i] = (int8_t)(i % 5 + 1); }

    uint64_t svl = 0; size_t sz = sizeof(svl);
    sysctlbyname("hw.optional.arm.sme_max_svl_b", &svl, &sz, NULL, 0);
    printf("sme_max_svl_b (streaming vector length, bytes) = %llu -> %llu bits\n", svl, svl*8);

    sme_smopa_test(a, b, out, (int)svl);
    printf("SMOPA executed OK. First 8 i32 accumulator lanes: ");
    for (int i = 0; i < 8; i++) printf("%d ", out[i]);
    printf("\n");
    return 0;
}
