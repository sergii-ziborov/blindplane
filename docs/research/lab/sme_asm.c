#include <stdio.h>
#include <stdint.h>
#include <time.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}

// Pure hand-written streaming region: no clang __arm_locally_streaming prologue,
// hence no base-SVE `cntd` outside streaming mode.
__attribute__((noinline)) static uint64_t sme_mul_loop(uint64_t iters, uint64_t *svl){
  uint64_t vl, sink;
  __asm__ volatile(
    "smstart sm\n"
    "rdvl %[vl], #1\n"
    "ptrue p0.d\n"
    "index z0.d, #1, #2\n" "index z1.d, #3, #2\n"
    "index z2.d, #5, #2\n" "index z3.d, #7, #2\n"
    "mov z8.d, #7\n" "mov z9.d, #11\n"
    "mov z12.d, #0\n" "mov z13.d, #0\n" "mov z14.d, #0\n" "mov z15.d, #0\n"
    "mov x8, %[it]\n"
    "1:\n"
    "umulh z16.d, z0.d, z8.d\n" "add z12.d, z12.d, z16.d\n" "mul z0.d, z0.d, z9.d\n"
    "umulh z17.d, z1.d, z8.d\n" "add z13.d, z13.d, z17.d\n" "mul z1.d, z1.d, z9.d\n"
    "umulh z18.d, z2.d, z8.d\n" "add z14.d, z14.d, z18.d\n" "mul z2.d, z2.d, z9.d\n"
    "umulh z19.d, z3.d, z8.d\n" "add z15.d, z15.d, z19.d\n" "mul z3.d, z3.d, z9.d\n"
    "subs x8, x8, #1\n"
    "b.ne 1b\n"
    "eor z12.d, z12.d, z13.d\n" "eor z14.d, z14.d, z15.d\n" "eor z12.d, z12.d, z14.d\n"
    "uaddv d20, p0, z12.d\n"
    "fmov %[sk], d20\n"
    "smstop sm\n"
    : [vl]"=&r"(vl), [sk]"=&r"(sink)
    : [it]"r"(iters)
    : "x8","p0","z0","z1","z2","z3","z8","z9","z12","z13","z14","z15",
      "z16","z17","z18","z19","z20","cc","memory");
  *svl = vl;
  return sink;
}
int main(void){
  uint64_t svl=0;
  uint64_t w = sme_mul_loop(1000,&svl); (void)w;
  printf("streaming VL = %llu bytes = %llu x u64 lanes\n",(unsigned long long)svl,(unsigned long long)svl/8);
  uint64_t lanes = svl/8, iters = 20000000ULL;
  double t0=now(); volatile uint64_t r=sme_mul_loop(iters,&svl); double t1=now(); (void)r;
  double muls=(double)iters*8.0*(double)lanes;  // 4 umulh + 4 mul per iter
  printf("SME streaming-SVE, 1 core: %.3f s -> %.2f G 64x64 multiplies/s\n",t1-t0,muls/(t1-t0)/1e9);
  return 0;
}
