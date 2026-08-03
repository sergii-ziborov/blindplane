#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
static double now(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec+1e-9*ts.tv_nsec;}

static void sem16(int ai,int bi,int64_t*o){
  int16_t a[32]={0},b[32]={0}; a[ai]=1; b[bi]=1;
  __asm__ volatile(
    "smstart\n\t ptrue p0.h\n\t ptrue p1.d\n\t"
    "ld1h {z0.h},p0/z,[%0]\n\t ld1h {z1.h},p0/z,[%1]\n\t"
    "zero {za}\n\t smopa za0.d,p0/m,p0/m,z0.h,z1.h\n\t"
    "mov x9,%2\n\t mov w12,#0\n\t"
    "2:\n\t mova z2.d,p1/m,za0h.d[w12,0]\n\t st1d {z2.d},p1,[x9]\n\t"
    "add x9,x9,#64\n\t add w12,w12,#1\n\t cmp w12,#8\n\t blt 2b\n\t"
    "smstop\n\t" :: "r"(a),"r"(b),"r"(o)
    :"z0","z1","z2","p0","p1","x9","x12","memory","cc");
}
#define RUN16(NAME,BODY,PER) \
static void NAME(int64_t iters,const int16_t*a,const int16_t*b){ \
  __asm__ volatile("smstart\n\t ptrue p0.h\n\t ld1h {z0.h},p0/z,[%1]\n\t ld1h {z1.h},p0/z,[%2]\n\t zero {za}\n\t" \
   "1:\n\t" BODY "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t" \
   :"+r"(iters):"r"(a),"r"(b):"z0","z1","p0","memory","cc"); }
RUN16(k16,
 "smopa za0.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za1.d,p0/m,p0/m,z0.h,z1.h\n\t"
 "smopa za2.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za3.d,p0/m,p0/m,z0.h,z1.h\n\t"
 "smopa za4.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za5.d,p0/m,p0/m,z0.h,z1.h\n\t"
 "smopa za6.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za7.d,p0/m,p0/m,z0.h,z1.h\n\t",8)
static void k8(int64_t iters,const int8_t*a,const int8_t*b){
  __asm__ volatile("smstart\n\t ptrue p0.b\n\t ld1b {z0.b},p0/z,[%1]\n\t ld1b {z1.b},p0/z,[%2]\n\t zero {za}\n\t"
   "1:\n\t"
   "smopa za0.s,p0/m,p0/m,z0.b,z1.b\n\t smopa za1.s,p0/m,p0/m,z0.b,z1.b\n\t"
   "smopa za2.s,p0/m,p0/m,z0.b,z1.b\n\t smopa za3.s,p0/m,p0/m,z0.b,z1.b\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(iters):"r"(a),"r"(b):"z0","z1","p0","memory","cc"); }
static void kread(int64_t iters,int64_t*buf){
  __asm__ volatile("smstart\n\t ptrue p1.d\n\t zero {za}\n\t"
   "1:\n\t mov w12,#0\n\t"
   "mova z2.d,p1/m,za0h.d[w12,0]\n\t st1d {z2.d},p1,[%1]\n\t add w12,w12,#1\n\t"
   "mova z3.d,p1/m,za0h.d[w12,0]\n\t st1d {z3.d},p1,[%1]\n\t add w12,w12,#1\n\t"
   "mova z4.d,p1/m,za0h.d[w12,0]\n\t st1d {z4.d},p1,[%1]\n\t add w12,w12,#1\n\t"
   "mova z5.d,p1/m,za0h.d[w12,0]\n\t st1d {z5.d},p1,[%1]\n\t add w12,w12,#1\n\t"
   "mova z6.d,p1/m,za0h.d[w12,0]\n\t st1d {z6.d},p1,[%1]\n\t add w12,w12,#1\n\t"
   "mova z7.d,p1/m,za0h.d[w12,0]\n\t st1d {z7.d},p1,[%1]\n\t add w12,w12,#1\n\t"
   "mova z8.d,p1/m,za0h.d[w12,0]\n\t st1d {z8.d},p1,[%1]\n\t add w12,w12,#1\n\t"
   "mova z9.d,p1/m,za0h.d[w12,0]\n\t st1d {z9.d},p1,[%1]\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(iters):"r"(buf):"z2","z3","z4","z5","z6","z7","z8","z9","x12","memory","cc"); }
static void krt(int64_t iters){
  __asm__ volatile("1:\n\t smstart\n\t smstop\n\t subs %0,%0,#1\n\t bne 1b\n\t":"+r"(iters)::"cc","memory"); }
static void kmul(int64_t iters,uint64_t*sink){
  uint64_t a=0x123456789abcdefULL,b=0xfedcba9876543ULL,lo=0,hi=0;
  __asm__ volatile("1:\n\t"
   "mul %0,%2,%3\n\t umulh %1,%2,%3\n\t mul %0,%2,%3\n\t umulh %1,%2,%3\n\t"
   "mul %0,%2,%3\n\t umulh %1,%2,%3\n\t mul %0,%2,%3\n\t umulh %1,%2,%3\n\t"
   "subs %4,%4,#1\n\t bne 1b\n\t":"+r"(lo),"+r"(hi),"+r"(a),"+r"(b),"+r"(iters)::"cc");
  *sink=lo+hi; }
int main(void){
  int64_t z[64]; sem16(3,5,z);
  printf("== SMOPA i16->i64, one-hot a[3]=1 b[5]=1 (nonzero => ZA[r][c] mapping) ==\n");
  for(int r=0;r<8;r++){printf("  row%d:",r);for(int c=0;c<8;c++)printf(" %lld",(long long)z[8*r+c]);printf("\n");}
  int16_t a16[32],b16[32]; for(int i=0;i<32;i++){a16[i]=i+1;b16[i]=2*i+1;}
  int8_t a8[64],b8[64]; for(int i=0;i<64;i++){a8[i]=i+1;b8[i]=2*i+1;}
  int64_t it=3000000; double t0,t1,n;
  printf("\n== single-thread P-core throughput ==\n");
  k16(1000,a16,b16); t0=now(); k16(it,a16,b16); t1=now(); n=(double)it*8;
  printf("SMOPA i16->i64: %.3f ns  %.2f G instr/s -> %.1f G int16x16 MAC/s\n",(t1-t0)/n*1e9,n/(t1-t0)/1e9,n*128/(t1-t0)/1e9);
  k8(1000,a8,b8); t0=now(); k8(it,a8,b8); t1=now(); n=(double)it*4;
  printf("SMOPA i8->i32 : %.3f ns  %.2f G instr/s -> %.1f G int8 MAC/s (%.0f GOPS)\n",(t1-t0)/n*1e9,n/(t1-t0)/1e9,n*1024/(t1-t0)/1e9,n*2048/(t1-t0)/1e9);
  int64_t buf[8]; kread(1000,buf); t0=now(); kread(1000000,buf); t1=now(); n=1000000.0*8;
  printf("ZA readout mova+st1d (64B/row): %.3f ns/row -> %.1f GB/s\n",(t1-t0)/n*1e9,n*64/(t1-t0)/1e9);
  krt(1000); t0=now(); krt(500000); t1=now();
  printf("smstart+smstop round trip: %.1f ns\n",(t1-t0)/500000*1e9);
  uint64_t s; kmul(1000,&s); t0=now(); kmul(it,&s); t1=now(); n=(double)it*4;
  printf("scalar mul+umulh 64x64->128: %.3f ns -> %.2f G products/s (sink %llu)\n",(t1-t0)/n*1e9,n/(t1-t0)/1e9,(unsigned long long)s);
  return 0;
}
