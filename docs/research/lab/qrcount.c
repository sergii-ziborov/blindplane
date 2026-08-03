#include <stdio.h>
#include <stdint.h>
#include <time.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
  return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}

/* EXACT copy of b10/b11's inner loops, but we measure iterations/sec so we can
   derive instructions-per-cycle and check which QR count is physically possible. */
static void sve_xar(int64_t it){
 __asm__ volatile("smstart sm\n\t" "1:\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#16\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#20\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#24\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#25\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#16\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#20\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#24\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#25\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#16\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#20\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#24\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#25\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#16\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#20\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#24\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#25\n\t"
  "subs %0,%0,#1\n\t bne 1b\n\t smstop sm\n\t":"+r"(it)::
  "z0","z1","z2","z3","z4","z5","z6","z7","z8","z9","z10","z11","z12","z13","z14","z15","memory","cc");}

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

int main(void){
  int64_t it=20000000;
  uint64_t t0=nowi(); sve_xar(it); uint64_t t1=nowi(); neon_qr(it); uint64_t t2=nowi();
  double sve_s=(t1-t0)/1e9, neon_s=(t2-t1)/1e9;
  double sve_ips=it/sve_s, neon_ips=it/neon_s;
  printf("SVE  loop: %.3f s for %lld iters -> %.2f Miter/s\n", sve_s,(long long)it, sve_ips/1e6);
  printf("NEON loop: %.3f s for %lld iters -> %.2f Miter/s\n", neon_s,(long long)it, neon_ips/1e6);
  printf("\nInstruction counts per iteration (counted from source):\n");
  printf("  SVE : 16 add + 16 xar + 2 loop = 34 instr, 4 vector quarter-rounds\n");
  printf("  NEON: 16 add + 16 eor + 4 rev32 + 12 shl + 12 usra + 2 loop = 62 instr, 4 vector quarter-rounds\n");
  printf("\nSVE  instr/s = %.2f G  (M4 P-core ~4.4GHz -> IPC %.2f)\n", sve_ips*34/1e9, sve_ips*34/4.4e9);
  printf("NEON instr/s = %.2f G  (M4 P-core ~4.4GHz -> IPC %.2f)\n", neon_ips*62/1e9, neon_ips*62/4.4e9);
  printf("\n--- ChaCha20 bytes/s implied by each QR accounting ---\n");
  printf("SVL=512b -> 16 lanes.  ChaCha20 = 80 quarter-rounds per 64-byte block.\n");
  double sve_qr_true = 4.0*16, sve_qr_b10 = 8.0*16;
  double neon_qr_true = 4.0*4, neon_qr_b10 = 8.0*4;
  printf("SVE  1thr: TRUE(4 QR/iter) %6.2f GB/s | b10 formula(8 QR/iter) %6.2f GB/s\n",
     sve_ips*sve_qr_true/80.0*64.0/1e9, sve_ips*sve_qr_b10/80.0*64.0/1e9);
  printf("NEON 1thr: TRUE(4 QR/iter) %6.2f GB/s | b10 formula(8 QR/iter) %6.2f GB/s\n",
     neon_ips*neon_qr_true/80.0*64.0/1e9, neon_ips*neon_qr_b10/80.0*64.0/1e9);
  return 0;
}
