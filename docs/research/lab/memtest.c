#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}
static void core_only(int64_t it, uint32_t*src, uint32_t*dst){
 __asm__ volatile("smstart sm\n\tsmstart za\n\t ptrue p0.s\n\t mov w12,#0\n\t1:\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#16\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#20\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#24\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#25\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#16\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#20\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#24\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#25\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#16\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#20\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#24\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#25\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#16\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#20\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#24\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#25\n\t"
  "add z16.s,z16.s,z17.s\n\t xar z19.s,z19.s,z16.s,#16\n\t add z18.s,z18.s,z19.s\n\t xar z17.s,z17.s,z18.s,#20\n\t"
  "add z16.s,z16.s,z17.s\n\t xar z19.s,z19.s,z16.s,#24\n\t add z18.s,z18.s,z19.s\n\t xar z17.s,z17.s,z18.s,#25\n\t"
  "add z20.s,z20.s,z21.s\n\t xar z23.s,z23.s,z20.s,#16\n\t add z22.s,z22.s,z23.s\n\t xar z21.s,z21.s,z22.s,#20\n\t"
  "add z20.s,z20.s,z21.s\n\t xar z23.s,z23.s,z20.s,#24\n\t add z22.s,z22.s,z23.s\n\t xar z21.s,z21.s,z22.s,#25\n\t"
  "subs %0,%0,#1\n\t bne 1b\n\tsmstop za\n\tsmstop sm\n\t"
  :"+r"(it):"r"(src),"r"(dst):"z0","z1","z2","z3","z4","z5","z6","z7","z8","z9","z10","z11","z12","z13","z14","z15","z16","z17","z18","z19","z20","z21","z22","z23","z24","z25","z26","z27","z28","z29","z30","z31","p0","memory","cc");}
static void core_mem(int64_t it, uint32_t*src, uint32_t*dst){
 __asm__ volatile("smstart sm\n\tsmstart za\n\t ptrue p0.s\n\t mov w12,#0\n\t1:\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#16\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#20\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#24\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#25\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#16\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#20\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#24\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#25\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#16\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#20\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#24\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#25\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#16\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#20\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#24\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#25\n\t"
  "add z16.s,z16.s,z17.s\n\t xar z19.s,z19.s,z16.s,#16\n\t add z18.s,z18.s,z19.s\n\t xar z17.s,z17.s,z18.s,#20\n\t"
  "add z16.s,z16.s,z17.s\n\t xar z19.s,z19.s,z16.s,#24\n\t add z18.s,z18.s,z19.s\n\t xar z17.s,z17.s,z18.s,#25\n\t"
  "add z20.s,z20.s,z21.s\n\t xar z23.s,z23.s,z20.s,#16\n\t add z22.s,z22.s,z23.s\n\t xar z21.s,z21.s,z22.s,#20\n\t"
  "add z20.s,z20.s,z21.s\n\t xar z23.s,z23.s,z20.s,#24\n\t add z22.s,z22.s,z23.s\n\t xar z21.s,z21.s,z22.s,#25\n\t"
  "ld1w {z24.s}, p0/z, [%1, #0, mul vl]\n\t eor z24.d, z24.d, z0.d\n\t st1w {z24.s}, p0, [%2, #0, mul vl]\n\t"
  "ld1w {z25.s}, p0/z, [%1, #1, mul vl]\n\t eor z25.d, z25.d, z1.d\n\t st1w {z25.s}, p0, [%2, #1, mul vl]\n\t"
  "ld1w {z26.s}, p0/z, [%1, #2, mul vl]\n\t eor z26.d, z26.d, z2.d\n\t st1w {z26.s}, p0, [%2, #2, mul vl]\n\t"
  "ld1w {z27.s}, p0/z, [%1, #3, mul vl]\n\t eor z27.d, z27.d, z3.d\n\t st1w {z27.s}, p0, [%2, #3, mul vl]\n\t"
  "ld1w {z28.s}, p0/z, [%1, #4, mul vl]\n\t eor z28.d, z28.d, z4.d\n\t st1w {z28.s}, p0, [%2, #4, mul vl]\n\t"
  "ld1w {z29.s}, p0/z, [%1, #5, mul vl]\n\t eor z29.d, z29.d, z5.d\n\t st1w {z29.s}, p0, [%2, #5, mul vl]\n\t"
  "ld1w {z30.s}, p0/z, [%1, #6, mul vl]\n\t eor z30.d, z30.d, z6.d\n\t st1w {z30.s}, p0, [%2, #6, mul vl]\n\t"
  "ld1w {z31.s}, p0/z, [%1, #7, mul vl]\n\t eor z31.d, z31.d, z7.d\n\t st1w {z31.s}, p0, [%2, #7, mul vl]\n\t"
  "ld1w {z24.s}, p0/z, [%1, #0, mul vl]\n\t eor z24.d, z24.d, z8.d\n\t st1w {z24.s}, p0, [%2, #0, mul vl]\n\t"
  "ld1w {z25.s}, p0/z, [%1, #1, mul vl]\n\t eor z25.d, z25.d, z9.d\n\t st1w {z25.s}, p0, [%2, #1, mul vl]\n\t"
  "ld1w {z26.s}, p0/z, [%1, #2, mul vl]\n\t eor z26.d, z26.d, z10.d\n\t st1w {z26.s}, p0, [%2, #2, mul vl]\n\t"
  "ld1w {z27.s}, p0/z, [%1, #3, mul vl]\n\t eor z27.d, z27.d, z11.d\n\t st1w {z27.s}, p0, [%2, #3, mul vl]\n\t"
  "ld1w {z28.s}, p0/z, [%1, #4, mul vl]\n\t eor z28.d, z28.d, z12.d\n\t st1w {z28.s}, p0, [%2, #4, mul vl]\n\t"
  "ld1w {z29.s}, p0/z, [%1, #5, mul vl]\n\t eor z29.d, z29.d, z13.d\n\t st1w {z29.s}, p0, [%2, #5, mul vl]\n\t"
  "ld1w {z30.s}, p0/z, [%1, #6, mul vl]\n\t eor z30.d, z30.d, z14.d\n\t st1w {z30.s}, p0, [%2, #6, mul vl]\n\t"
  "ld1w {z31.s}, p0/z, [%1, #7, mul vl]\n\t eor z31.d, z31.d, z15.d\n\t st1w {z31.s}, p0, [%2, #7, mul vl]\n\t"
  "subs %0,%0,#1\n\t bne 1b\n\tsmstop za\n\tsmstop sm\n\t"
  :"+r"(it):"r"(src),"r"(dst):"z0","z1","z2","z3","z4","z5","z6","z7","z8","z9","z10","z11","z12","z13","z14","z15","z16","z17","z18","z19","z20","z21","z22","z23","z24","z25","z26","z27","z28","z29","z30","z31","p0","memory","cc");}
static void core_mem_za(int64_t it, uint32_t*src, uint32_t*dst){
 __asm__ volatile("smstart sm\n\tsmstart za\n\t ptrue p0.s\n\t mov w12,#0\n\t1:\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#16\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#20\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#24\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#25\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#16\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#20\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#24\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#25\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#16\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#20\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#24\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#25\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#16\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#20\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#24\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#25\n\t"
  "add z16.s,z16.s,z17.s\n\t xar z19.s,z19.s,z16.s,#16\n\t add z18.s,z18.s,z19.s\n\t xar z17.s,z17.s,z18.s,#20\n\t"
  "add z16.s,z16.s,z17.s\n\t xar z19.s,z19.s,z16.s,#24\n\t add z18.s,z18.s,z19.s\n\t xar z17.s,z17.s,z18.s,#25\n\t"
  "add z20.s,z20.s,z21.s\n\t xar z23.s,z23.s,z20.s,#16\n\t add z22.s,z22.s,z23.s\n\t xar z21.s,z21.s,z22.s,#20\n\t"
  "add z20.s,z20.s,z21.s\n\t xar z23.s,z23.s,z20.s,#24\n\t add z22.s,z22.s,z23.s\n\t xar z21.s,z21.s,z22.s,#25\n\t"
  "ld1w {z24.s}, p0/z, [%1, #0, mul vl]\n\t eor z24.d, z24.d, z0.d\n\t st1w {z24.s}, p0, [%2, #0, mul vl]\n\t"
  "ld1w {z25.s}, p0/z, [%1, #1, mul vl]\n\t eor z25.d, z25.d, z1.d\n\t st1w {z25.s}, p0, [%2, #1, mul vl]\n\t"
  "ld1w {z26.s}, p0/z, [%1, #2, mul vl]\n\t eor z26.d, z26.d, z2.d\n\t st1w {z26.s}, p0, [%2, #2, mul vl]\n\t"
  "ld1w {z27.s}, p0/z, [%1, #3, mul vl]\n\t eor z27.d, z27.d, z3.d\n\t st1w {z27.s}, p0, [%2, #3, mul vl]\n\t"
  "ld1w {z28.s}, p0/z, [%1, #4, mul vl]\n\t eor z28.d, z28.d, z4.d\n\t st1w {z28.s}, p0, [%2, #4, mul vl]\n\t"
  "ld1w {z29.s}, p0/z, [%1, #5, mul vl]\n\t eor z29.d, z29.d, z5.d\n\t st1w {z29.s}, p0, [%2, #5, mul vl]\n\t"
  "ld1w {z30.s}, p0/z, [%1, #6, mul vl]\n\t eor z30.d, z30.d, z6.d\n\t st1w {z30.s}, p0, [%2, #6, mul vl]\n\t"
  "ld1w {z31.s}, p0/z, [%1, #7, mul vl]\n\t eor z31.d, z31.d, z7.d\n\t st1w {z31.s}, p0, [%2, #7, mul vl]\n\t"
  "ld1w {z24.s}, p0/z, [%1, #0, mul vl]\n\t eor z24.d, z24.d, z8.d\n\t st1w {z24.s}, p0, [%2, #0, mul vl]\n\t"
  "ld1w {z25.s}, p0/z, [%1, #1, mul vl]\n\t eor z25.d, z25.d, z9.d\n\t st1w {z25.s}, p0, [%2, #1, mul vl]\n\t"
  "ld1w {z26.s}, p0/z, [%1, #2, mul vl]\n\t eor z26.d, z26.d, z10.d\n\t st1w {z26.s}, p0, [%2, #2, mul vl]\n\t"
  "ld1w {z27.s}, p0/z, [%1, #3, mul vl]\n\t eor z27.d, z27.d, z11.d\n\t st1w {z27.s}, p0, [%2, #3, mul vl]\n\t"
  "ld1w {z28.s}, p0/z, [%1, #4, mul vl]\n\t eor z28.d, z28.d, z12.d\n\t st1w {z28.s}, p0, [%2, #4, mul vl]\n\t"
  "ld1w {z29.s}, p0/z, [%1, #5, mul vl]\n\t eor z29.d, z29.d, z13.d\n\t st1w {z29.s}, p0, [%2, #5, mul vl]\n\t"
  "ld1w {z30.s}, p0/z, [%1, #6, mul vl]\n\t eor z30.d, z30.d, z14.d\n\t st1w {z30.s}, p0, [%2, #6, mul vl]\n\t"
  "ld1w {z31.s}, p0/z, [%1, #7, mul vl]\n\t eor z31.d, z31.d, z15.d\n\t st1w {z31.s}, p0, [%2, #7, mul vl]\n\t"
  "mova za0h.s[w12,0], p0/m, z0.s\n\t"
  "mova za0h.s[w12,1], p0/m, z1.s\n\t"
  "mova za0h.s[w12,2], p0/m, z2.s\n\t"
  "mova za0h.s[w12,3], p0/m, z3.s\n\t"
  "mova za0h.s[w12,0], p0/m, z4.s\n\t"
  "mova za0h.s[w12,1], p0/m, z5.s\n\t"
  "mova za0h.s[w12,2], p0/m, z6.s\n\t"
  "mova za0h.s[w12,3], p0/m, z7.s\n\t"
  "mova za0h.s[w12,0], p0/m, z8.s\n\t"
  "mova za0h.s[w12,1], p0/m, z9.s\n\t"
  "mova za0h.s[w12,2], p0/m, z10.s\n\t"
  "mova za0h.s[w12,3], p0/m, z11.s\n\t"
  "mova za0h.s[w12,0], p0/m, z12.s\n\t"
  "mova za0h.s[w12,1], p0/m, z13.s\n\t"
  "mova za0h.s[w12,2], p0/m, z14.s\n\t"
  "mova za0h.s[w12,3], p0/m, z15.s\n\t"
  "mova z0.s, p0/m, za0v.s[w12,0]\n\t"
  "mova z1.s, p0/m, za0v.s[w12,1]\n\t"
  "mova z2.s, p0/m, za0v.s[w12,2]\n\t"
  "mova z3.s, p0/m, za0v.s[w12,3]\n\t"
  "mova z4.s, p0/m, za0v.s[w12,0]\n\t"
  "mova z5.s, p0/m, za0v.s[w12,1]\n\t"
  "mova z6.s, p0/m, za0v.s[w12,2]\n\t"
  "mova z7.s, p0/m, za0v.s[w12,3]\n\t"
  "mova z8.s, p0/m, za0v.s[w12,0]\n\t"
  "mova z9.s, p0/m, za0v.s[w12,1]\n\t"
  "mova z10.s, p0/m, za0v.s[w12,2]\n\t"
  "mova z11.s, p0/m, za0v.s[w12,3]\n\t"
  "mova z12.s, p0/m, za0v.s[w12,0]\n\t"
  "mova z13.s, p0/m, za0v.s[w12,1]\n\t"
  "mova z14.s, p0/m, za0v.s[w12,2]\n\t"
  "mova z15.s, p0/m, za0v.s[w12,3]\n\t"
  "subs %0,%0,#1\n\t bne 1b\n\tsmstop za\n\tsmstop sm\n\t"
  :"+r"(it):"r"(src),"r"(dst):"z0","z1","z2","z3","z4","z5","z6","z7","z8","z9","z10","z11","z12","z13","z14","z15","z16","z17","z18","z19","z20","z21","z22","z23","z24","z25","z26","z27","z28","z29","z30","z31","p0","za","memory","cc");}
int main(void){
  setbuf(stdout,NULL);
  int64_t it=4000000;
  uint32_t *a=aligned_alloc(64,1<<20), *b=aligned_alloc(64,1<<20);
  for(int i=0;i<(1<<18);i++){a[i]=i;b[i]=0;}
  double qr=6*4.0*16.0;
  struct {const char*n; void(*f)(int64_t,uint32_t*,uint32_t*);} t[]={
    {"SSVE core only (b10/b11 style, NO memory traffic)",core_only},
    {"SSVE core + ld1w/eor/st1w (real encryption traffic)",core_mem},
    {"SSVE core + mem + ZA transpose (contiguous blocks)",core_mem_za}};
  printf("single-thread SSVE ChaCha20, correct QR accounting, warmed\n");
  for(int i=0;i<3;i++){
    t[i].f(200000,a,b);
    double best=0;
    for(int r=0;r<3;r++){uint64_t t0=nowi(); t[i].f(it,a,b); uint64_t t1=nowi();
      double g=(double)it*qr/80.0*64.0/((t1-t0)/1e9)/1e9; if(g>best)best=g;}
    printf("  %-52s %6.2f GB/s\n", t[i].n, best);
  }
  return 0;
}
