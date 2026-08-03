#include <stdio.h>
#include <stdint.h>
#include <time.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
  return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}
#define CL "memory","cc","v8","v9","v10","v11","v12","v13","v14","v15"
/* ChaCha quarter-round shape in STREAMING SVE (512-bit z regs, 16 u32 lanes each) */
static void sve_qr(int64_t iters){
  __asm__ volatile("smstart sm\n\t ptrue p0.s\n\t"
   "1:\n\t"
   /* 4 independent QR chains on z0..z15 : add, eor, rotate(=lsl|lsr via xar? use revb/ror) */
   "add z0.s,z0.s,z1.s\n\t eor z3.s,z3.s,z0.s\n\t revh z3.s,p0/m,z3.s\n\t"
   "add z2.s,z2.s,z3.s\n\t eor z1.s,z1.s,z2.s\n\t lsl z16.s,z1.s,#12\n\t lsr z1.s,z1.s,#20\n\t orr z1.d,z1.d,z16.d\n\t"
   "add z4.s,z4.s,z5.s\n\t eor z7.s,z7.s,z4.s\n\t revh z7.s,p0/m,z7.s\n\t"
   "add z6.s,z6.s,z7.s\n\t eor z5.s,z5.s,z6.s\n\t lsl z17.s,z5.s,#12\n\t lsr z5.s,z5.s,#20\n\t orr z5.d,z5.d,z17.d\n\t"
   "add z8.s,z8.s,z9.s\n\t eor z11.s,z11.s,z8.s\n\t revh z11.s,p0/m,z11.s\n\t"
   "add z10.s,z10.s,z11.s\n\t eor z9.s,z9.s,z10.s\n\t lsl z18.s,z9.s,#12\n\t lsr z9.s,z9.s,#20\n\t orr z9.d,z9.d,z18.d\n\t"
   "add z12.s,z12.s,z13.s\n\t eor z15.s,z15.s,z12.s\n\t revh z15.s,p0/m,z15.s\n\t"
   "add z14.s,z14.s,z15.s\n\t eor z13.s,z13.s,z14.s\n\t lsl z19.s,z13.s,#12\n\t lsr z13.s,z13.s,#20\n\t orr z13.d,z13.d,z19.d\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop sm\n\t"
   :"+r"(iters)::"p0","z0","z1","z2","z3","z4","z5","z6","z7","z8","z9","z10","z11",
    "z12","z13","z14","z15","z16","z17","z18","z19",CL);}
/* same shape in NEON (128-bit, 4 u32 lanes) */
static void neon_qr(int64_t iters){
  __asm__ volatile(
   "1:\n\t"
   "add v0.4s,v0.4s,v1.4s\n\t eor v3.16b,v3.16b,v0.16b\n\t rev32 v3.8h,v3.8h\n\t"
   "add v2.4s,v2.4s,v3.4s\n\t eor v1.16b,v1.16b,v2.16b\n\t shl v16.4s,v1.4s,#12\n\t usra v16.4s,v1.4s,#20\n\t mov v1.16b,v16.16b\n\t"
   "add v4.4s,v4.4s,v5.4s\n\t eor v7.16b,v7.16b,v4.16b\n\t rev32 v7.8h,v7.8h\n\t"
   "add v6.4s,v6.4s,v7.4s\n\t eor v5.16b,v5.16b,v6.16b\n\t shl v17.4s,v5.4s,#12\n\t usra v17.4s,v5.4s,#20\n\t mov v5.16b,v17.16b\n\t"
   "add v8.4s,v8.4s,v9.4s\n\t eor v11.16b,v11.16b,v8.16b\n\t rev32 v11.8h,v11.8h\n\t"
   "add v10.4s,v10.4s,v11.4s\n\t eor v9.16b,v9.16b,v10.16b\n\t shl v18.4s,v9.4s,#12\n\t usra v18.4s,v9.4s,#20\n\t mov v9.16b,v18.16b\n\t"
   "add v12.4s,v12.4s,v13.4s\n\t eor v15.16b,v15.16b,v12.16b\n\t rev32 v15.8h,v15.8h\n\t"
   "add v14.4s,v14.4s,v15.4s\n\t eor v13.16b,v13.16b,v14.16b\n\t shl v19.4s,v13.4s,#12\n\t usra v19.4s,v13.4s,#20\n\t mov v13.16b,v19.16b\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t"
   :"+r"(iters)::"v0","v1","v2","v3","v4","v5","v6","v7","v8","v9","v10","v11",
    "v12","v13","v14","v15","v16","v17","v18","v19","memory","cc");}
int main(void){
  int64_t it=20000000; uint64_t t0,t1;
  /* each iteration: 4 chains x 2 "half quarter-rounds" -> count 32-bit lane-ops */
  sve_qr(1000); t0=nowi(); sve_qr(it); t1=nowi();
  double ns=(double)(t1-t0)/it;
  /* per iter: 8 add + 8 eor + 4 revb + 4*(lsl+lsr+orr)=12  => 32 vector instrs, 16 lanes each */
  printf("STREAMING SVE (512b): %.2f ns/iter -> %.1f G vec-instr/s, %.1f G u32-lane-ops/s\n",
    ns, 32.0/ns, 32.0*16/ns);
  neon_qr(1000); t0=nowi(); neon_qr(it); t1=nowi();
  double ns2=(double)(t1-t0)/it;
  /* per iter: 8 add + 8 eor + 4 rev32 + 4*(shl+usra+mov)=12 => 32 instrs, 4 lanes each */
  printf("NEON          (128b): %.2f ns/iter -> %.1f G vec-instr/s, %.1f G u32-lane-ops/s\n",
    ns2, 32.0/ns2, 32.0*4/ns2);
  printf("\nstreaming-SVE vs NEON lane-throughput ratio: %.2fx\n", (32.0*16/ns)/(32.0*4/ns2));
  return 0;
}
