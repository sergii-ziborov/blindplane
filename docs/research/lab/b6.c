#include <stdio.h>
#include <stdint.h>
#include <time.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
  return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}
#define CL "memory","cc","v8","v9","v10","v11","v12","v13","v14","v15"

/* direct ZA->memory store: st1d {za0h.d[w12,0]}, p0, [x] */
static void st_za(int64_t iters,void*buf){
  __asm__ volatile("smstart\n\t ptrue p0.d\n\t zero {za}\n\t"
   "1:\n\t mov x9,%1\n\t mov w12,#0\n\t"
   "st1d {za0h.d[w12,0]},p0,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p0,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p0,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p0,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p0,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p0,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p0,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p0,[x9]\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(iters):"r"(buf):"p0","x9","x12",CL);}

/* full 4KB ZA save via STR ZA (64 slices) */
static void str_za(int64_t iters,void*buf){
  __asm__ volatile("smstart\n\t"
   "1:\n\t mov w12,#0\n\t mov x9,%1\n\t"
   "2:\n\t str za[w12,0],[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t cmp w12,#64\n\t blt 2b\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(iters):"r"(buf):"x9","x12",CL);}

/* mova to z then st1d (previous method), independent addresses */
static void mova_st(int64_t iters,void*buf){
  __asm__ volatile("smstart\n\t ptrue p0.d\n\t zero {za}\n\t"
   "1:\n\t mov x9,%1\n\t mov w12,#0\n\t"
   "mova z2.d,p0/m,za0h.d[w12,0]\n\t add w12,w12,#1\n\t"
   "mova z3.d,p0/m,za0h.d[w12,0]\n\t add w12,w12,#1\n\t"
   "mova z4.d,p0/m,za0h.d[w12,0]\n\t add w12,w12,#1\n\t"
   "mova z5.d,p0/m,za0h.d[w12,0]\n\t add w12,w12,#1\n\t"
   "mova z6.d,p0/m,za0h.d[w12,0]\n\t add w12,w12,#1\n\t"
   "mova z7.d,p0/m,za0h.d[w12,0]\n\t add w12,w12,#1\n\t"
   "mova z16.d,p0/m,za0h.d[w12,0]\n\t add w12,w12,#1\n\t"
   "mova z17.d,p0/m,za0h.d[w12,0]\n\t"
   "st1d {z2.d},p0,[x9]\n\t add x9,x9,#64\n\t st1d {z3.d},p0,[x9]\n\t add x9,x9,#64\n\t"
   "st1d {z4.d},p0,[x9]\n\t add x9,x9,#64\n\t st1d {z5.d},p0,[x9]\n\t add x9,x9,#64\n\t"
   "st1d {z6.d},p0,[x9]\n\t add x9,x9,#64\n\t st1d {z7.d},p0,[x9]\n\t add x9,x9,#64\n\t"
   "st1d {z16.d},p0,[x9]\n\t add x9,x9,#64\n\t st1d {z17.d},p0,[x9]\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(iters):"r"(buf):"z2","z3","z4","z5","z6","z7","z16","z17","p0","x9","x12",CL);}

/* realistic crypto shape: zero+load+smopa+store one 8x8 tile, per call */
static void one_mul(int64_t iters,const int16_t*a,const int16_t*b,void*out){
  __asm__ volatile("smstart\n\t ptrue p0.h\n\t ptrue p1.d\n\t"
   "1:\n\t"
   "ld1h {z0.h},p0/z,[%1]\n\t ld1h {z1.h},p0/z,[%2]\n\t"
   "zero {za}\n\t"
   "smopa za0.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "mov x9,%3\n\t mov w12,#0\n\t"
   "st1d {za0h.d[w12,0]},p1,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p1,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p1,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p1,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p1,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p1,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p1,[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t"
   "st1d {za0h.d[w12,0]},p1,[x9]\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(iters):"r"(a),"r"(b),"r"(out):"z0","z1","p0","p1","x9","x12",CL);}
int main(void){
  static char buf[8192] __attribute__((aligned(256)));
  int16_t a[32],b[32]; for(int i=0;i<32;i++){a[i]=i+1;b[i]=2*i+1;}
  uint64_t t0,t1; double n;
  int64_t it=1000000;
  st_za(1000,buf); t0=nowi(); st_za(it,buf); t1=nowi(); n=(double)it*8;
  printf("ST1D from ZA (8 rows x 64B): %.2f ns/row -> %.1f GB/s\n",(double)(t1-t0)/n,n*64/(double)(t1-t0));
  mova_st(1000,buf); t0=nowi(); mova_st(it,buf); t1=nowi(); n=(double)it*8;
  printf("MOVA+ST1D    (8 rows x 64B): %.2f ns/row -> %.1f GB/s\n",(double)(t1-t0)/n,n*64/(double)(t1-t0));
  str_za(1000,buf); t0=nowi(); str_za(200000,buf); t1=nowi(); n=200000.0*64;
  printf("STR ZA full 4KB tile array : %.2f ns/64B slice -> %.1f GB/s\n",(double)(t1-t0)/n,n*64/(double)(t1-t0));
  one_mul(1000,a,b,buf); t0=nowi(); one_mul(it,a,b,buf); t1=nowi(); n=(double)it;
  printf("\nfull kernel (ld+zero+1 SMOPA+store 8x8 i64 tile): %.1f ns/op, %.2f M ops/s\n",
     (double)(t1-t0)/n, n/(double)(t1-t0)*1000.0);
  return 0;
}
