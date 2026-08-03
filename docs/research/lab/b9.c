#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}
#define CL "memory","cc","v8","v9","v10","v11","v12","v13","v14","v15"
/* ChaCha QR using XAR (xor+rotate fused) in streaming SVE, 512-bit */
static void sve_xar(int64_t it){
 __asm__ volatile("smstart sm\n\t"
  "1:\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#16\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#20\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#24\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#25\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#16\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#20\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#24\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#25\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#16\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#20\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#24\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#25\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#16\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#20\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#24\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#25\n\t"
  "subs %0,%0,#1\n\t bne 1b\n\t smstop sm\n\t":"+r"(it)::
  "z0","z1","z2","z3","z4","z5","z6","z7","z8","z9","z10","z11","z12","z13","z14","z15",CL);}
/* NEON equivalent using XAR (FEAT_SHA3 gives 64-bit XAR only; use eor+shl/usra for 32-bit) */
static void neon_qr(int64_t it){
 __asm__ volatile("1:\n\t"
  "add v0.4s,v0.4s,v1.4s\n\t eor v3.16b,v3.16b,v0.16b\n\t rev32 v3.8h,v3.8h\n\t"
  "add v2.4s,v2.4s,v3.4s\n\t eor v20.16b,v1.16b,v2.16b\n\t shl v1.4s,v20.4s,#12\n\t usra v1.4s,v20.4s,#20\n\t"
  "add v0.4s,v0.4s,v1.4s\n\t eor v20.16b,v3.16b,v0.16b\n\t shl v3.4s,v20.4s,#8\n\t usra v3.4s,v20.4s,#24\n\t"
  "add v2.4s,v2.4s,v3.4s\n\t eor v20.16b,v1.16b,v2.16b\n\t shl v1.4s,v20.4s,#7\n\t usra v1.4s,v20.4s,#25\n\t"
  "add v4.4s,v4.4s,v5.4s\n\t eor v7.16b,v7.16b,v4.16b\n\t rev32 v7.8h,v7.8h\n\t"
  "add v6.4s,v6.4s,v7.4s\n\t eor v21.16b,v5.16b,v6.16b\n\t shl v5.4s,v21.4s,#12\n\t usra v5.4s,v21.4s,#20\n\t"
  "add v4.4s,v4.4s,v5.4s\n\t eor v21.16b,v7.16b,v4.16b\n\t shl v7.4s,v21.4s,#8\n\t usra v7.4s,v21.4s,#24\n\t"
  "add v6.4s,v6.4s,v7.4s\n\t eor v21.16b,v5.16b,v6.16b\n\t shl v5.4s,v21.4s,#7\n\t usra v5.4s,v21.4s,#25\n\t"
  "add v8.4s,v8.4s,v9.4s\n\t eor v11.16b,v11.16b,v8.16b\n\t rev32 v11.8h,v11.8h\n\t"
  "add v10.4s,v10.4s,v11.4s\n\t eor v22.16b,v9.16b,v10.16b\n\t shl v9.4s,v22.4s,#12\n\t usra v9.4s,v22.4s,#20\n\t"
  "add v8.4s,v8.4s,v9.4s\n\t eor v22.16b,v11.16b,v8.16b\n\t shl v11.4s,v22.4s,#8\n\t usra v11.4s,v22.4s,#24\n\t"
  "add v10.4s,v10.4s,v11.4s\n\t eor v22.16b,v9.16b,v10.16b\n\t shl v9.4s,v22.4s,#7\n\t usra v9.4s,v22.4s,#25\n\t"
  "add v12.4s,v12.4s,v13.4s\n\t eor v15.16b,v15.16b,v12.16b\n\t rev32 v15.8h,v15.8h\n\t"
  "add v14.4s,v14.4s,v15.4s\n\t eor v23.16b,v13.16b,v14.16b\n\t shl v13.4s,v23.4s,#12\n\t usra v13.4s,v23.4s,#20\n\t"
  "add v12.4s,v12.4s,v13.4s\n\t eor v23.16b,v15.16b,v12.16b\n\t shl v15.4s,v23.4s,#8\n\t usra v15.4s,v23.4s,#24\n\t"
  "add v14.4s,v14.4s,v15.4s\n\t eor v23.16b,v13.16b,v14.16b\n\t shl v13.4s,v23.4s,#7\n\t usra v13.4s,v23.4s,#25\n\t"
  "subs %0,%0,#1\n\t bne 1b\n\t":"+r"(it)::
  "v0","v1","v2","v3","v4","v5","v6","v7","v8","v9","v10","v11","v12","v13","v14","v15",
  "v20","v21","v22","v23","memory","cc");}
/* streaming SVE 64x64->128 : mul + umulh, 8 lanes */
static void sve_mul(int64_t it){
 __asm__ volatile("smstart sm\n\t"
  "1:\n\t"
  "mul z0.d,z10.d,z11.d\n\t umulh z1.d,z10.d,z11.d\n\t"
  "mul z2.d,z12.d,z13.d\n\t umulh z3.d,z12.d,z13.d\n\t"
  "mul z4.d,z14.d,z15.d\n\t umulh z5.d,z14.d,z15.d\n\t"
  "mul z6.d,z16.d,z17.d\n\t umulh z7.d,z16.d,z17.d\n\t"
  "subs %0,%0,#1\n\t bne 1b\n\t smstop sm\n\t":"+r"(it)::
  "z0","z1","z2","z3","z4","z5","z6","z7",CL);}
static void scalar_mul(int64_t it){
 uint64_t a=0x123456789abcdefULL,b=0xfedcba98765ULL,lo,hi;
 __asm__ volatile("1:\n\t"
  "mul %0,%2,%3\n\t umulh %1,%2,%3\n\t mul %0,%2,%3\n\t umulh %1,%2,%3\n\t"
  "mul %0,%2,%3\n\t umulh %1,%2,%3\n\t mul %0,%2,%3\n\t umulh %1,%2,%3\n\t"
  "subs %4,%4,#1\n\t bne 1b\n\t":"=&r"(lo),"=&r"(hi),"+r"(a),"+r"(b),"+r"(it)::"cc");}
int main(void){
  int64_t it=10000000; uint64_t t0,t1; double ns;
  sve_xar(1000); t0=nowi(); sve_xar(it); t1=nowi(); ns=(double)(t1-t0)/it;
  /* per iter: 4 chains x 1 full ChaCha double-quarter-round(=2 QR) on 16 u32 lanes
     = 4 QR-pairs. ChaCha20 block = 20 rounds x 4 QR = 80 QR. lanes=16 -> 4 blocks/reg-set */
  double sve_qr_per_s = 4.0*2/ns;     /* QRs per ns, each on 16 lanes */
  printf("STREAMING SVE ChaCha (XAR): %.2f ns/iter -> %.2f G QR/s x16 lanes = %.1f G lane-QR/s\n",
     ns, sve_qr_per_s, sve_qr_per_s*16);
  double sve_bps = sve_qr_per_s*16/80.0*64.0; /* bytes/ns = GB/s */
  printf("   => ChaCha20 core ceiling: %.2f GB/s single thread\n", sve_bps);
  neon_qr(1000); t0=nowi(); neon_qr(it); t1=nowi(); ns=(double)(t1-t0)/it;
  double n_qr=4.0*2/ns;
  printf("NEON ChaCha:                %.2f ns/iter -> %.2f G QR/s x4 lanes = %.1f G lane-QR/s\n",
     ns, n_qr, n_qr*4);
  double n_bps=n_qr*4/80.0*64.0;
  printf("   => ChaCha20 core ceiling: %.2f GB/s single thread\n", n_bps);
  printf("   RATIO streaming-SVE / NEON = %.2fx\n\n", sve_bps/n_bps);
  sve_mul(1000); t0=nowi(); sve_mul(it); t1=nowi(); ns=(double)(t1-t0)/it;
  printf("STREAMING SVE mul+umulh .d: %.2f ns/iter -> %.2f G 64x64->128 products/s (8 lanes x4)\n",
     ns, 4.0*8/ns);
  scalar_mul(1000); t0=nowi(); scalar_mul(it); t1=nowi(); ns=(double)(t1-t0)/it;
  printf("scalar mul+umulh:           %.2f ns/iter -> %.2f G products/s\n", ns, 4.0/ns);
  return 0;
}
