#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <dispatch/dispatch.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
  return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}
#define CL "memory","cc","v8","v9","v10","v11","v12","v13","v14","v15"

static void one_mul(int64_t iters,const int16_t*a,const int16_t*b,void*out){
  __asm__ volatile("smstart\n\t ptrue p0.h\n\t ptrue p1.d\n\t"
   "1:\n\t ld1h {z0.h},p0/z,[%1]\n\t ld1h {z1.h},p0/z,[%2]\n\t"
   "zero {za}\n\t smopa za0.d,p0/m,p0/m,z0.h,z1.h\n\t"
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

/* BATCHED: 8 field muls into za0.d..za7.d, single bulk STR ZA drain (64 slices) */
static void batch8(int64_t iters,const int16_t*a,const int16_t*b,void*out){
  __asm__ volatile("smstart\n\t ptrue p0.h\n\t"
   "1:\n\t ld1h {z0.h},p0/z,[%1]\n\t ld1h {z1.h},p0/z,[%2]\n\t"
   "zero {za}\n\t"
   "smopa za0.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za1.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "smopa za2.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za3.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "smopa za4.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za5.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "smopa za6.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za7.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "mov w12,#0\n\t mov x9,%3\n\t"
   "2:\n\t str za[w12,0],[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t cmp w12,#64\n\t blt 2b\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(iters):"r"(a),"r"(b),"r"(out):"z0","z1","p0","x9","x12",CL);}

static void zero_only(int64_t iters){
  __asm__ volatile("smstart\n\t 1:\n\t zero {za}\n\t subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(iters)::CL);}

static void smopa_only(int64_t iters,const int16_t*a,const int16_t*b){
  __asm__ volatile("smstart\n\t ptrue p0.h\n\t zero {za}\n\t"
   "ld1h {z0.h},p0/z,[%1]\n\t ld1h {z1.h},p0/z,[%2]\n\t"
   "1:\n\t"
   "smopa za0.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za1.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "smopa za2.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za3.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "smopa za4.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za5.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "smopa za6.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za7.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(iters):"r"(a),"r"(b):"z0","z1","p0",CL);}

static void modeswitch(int64_t iters){
  __asm__ volatile("1:\n\t smstart\n\t smstop\n\t subs %0,%0,#1\n\t bne 1b\n\t"
   :"+r"(iters)::CL);}

typedef struct { uint64_t l[5]; } fe;
#define M51 (((uint64_t)1<<51)-1)
static inline fe fe_mul(const fe*x,const fe*y){
  __uint128_t a0=x->l[0],a1=x->l[1],a2=x->l[2],a3=x->l[3],a4=x->l[4];
  __uint128_t b0=y->l[0],b1=y->l[1],b2=y->l[2],b3=y->l[3],b4=y->l[4];
  __uint128_t b1_19=b1*19,b2_19=b2*19,b3_19=b3*19,b4_19=b4*19;
  __uint128_t r0=a0*b0+a1*b4_19+a2*b3_19+a3*b2_19+a4*b1_19;
  __uint128_t r1=a0*b1+a1*b0+a2*b4_19+a3*b3_19+a4*b2_19;
  __uint128_t r2=a0*b2+a1*b1+a2*b0+a3*b4_19+a4*b3_19;
  __uint128_t r3=a0*b3+a1*b2+a2*b1+a3*b0+a4*b4_19;
  __uint128_t r4=a0*b4+a1*b3+a2*b2+a3*b1+a4*b0;
  fe o; uint64_t c;
  c=(uint64_t)(r0>>51); o.l[0]=(uint64_t)r0&M51; r1+=c;
  c=(uint64_t)(r1>>51); o.l[1]=(uint64_t)r1&M51; r2+=c;
  c=(uint64_t)(r2>>51); o.l[2]=(uint64_t)r2&M51; r3+=c;
  c=(uint64_t)(r3>>51); o.l[3]=(uint64_t)r3&M51; r4+=c;
  c=(uint64_t)(r4>>51); o.l[4]=(uint64_t)r4&M51;
  o.l[0]+=c*19; o.l[1]+=o.l[0]>>51; o.l[0]&=M51;
  return o;
}
/* 16-bit-limb carry propagation: what SME output would force us to do.
   31 columns of i64 accumulators -> 16 limbs of 16 bits, serial. */
static inline void carry16(int64_t*acc,uint16_t*out){
  int64_t c=0;
  for(int i=0;i<31;i++){ int64_t v=acc[i]+c; out[i&15]=(uint16_t)(v&0xffff); c=v>>16; }
}

int main(int argc,char**argv){
  int stage = argc>1 ? atoi(argv[1]) : 0;
  pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0);
  static char buf[8192] __attribute__((aligned(256)));
  int16_t a[32],b[32]; for(int i=0;i<32;i++){a[i]=i+1;b[i]=2*i+1;}
  uint64_t t0,t1; double n; int64_t it=1000000;

  if(stage==0||stage==1){
  one_mul(1000,a,b,buf); t0=nowi(); one_mul(it,a,b,buf); t1=nowi(); n=(double)it;
  printf("A  1-tile kernel (the claim's):    %8.2f ns/field-mul\n",(double)(t1-t0)/n); fflush(stdout);}

  if(stage==0||stage==2){
  batch8(100,a,b,buf); t0=nowi(); batch8(it/8,a,b,buf); t1=nowi(); n=(double)(it/8);
  printf("B  batch-8 + bulk STR ZA drain:    %8.2f ns/batch = %7.2f ns/field-mul\n",
     (double)(t1-t0)/n,(double)(t1-t0)/n/8.0); fflush(stdout);}

  if(stage==0||stage==3){
  zero_only(1000); t0=nowi(); zero_only(it); t1=nowi();
  printf("C  zero {za} alone:                %8.2f ns\n",(double)(t1-t0)/(double)it); fflush(stdout);}

  if(stage==0||stage==4){
  smopa_only(1000,a,b); t0=nowi(); smopa_only(it,a,b); t1=nowi(); n=(double)it*8;
  printf("D  SMOPA issue rate (no drain):    %8.3f ns/SMOPA -> %.1f G int16 MAC/s\n",
     (double)(t1-t0)/n, n*256/(double)(t1-t0)); fflush(stdout);}

  if(stage==0||stage==5){
  modeswitch(1000); t0=nowi(); modeswitch(it); t1=nowi();
  printf("E  smstart+smstop pair:            %8.2f ns\n",(double)(t1-t0)/(double)it); fflush(stdout);}

  if(stage==0||stage==6){
  fe x={{1,2,3,4,5}},y={{6,7,8,9,10}};
  fe_mul(&x,&y); t0=nowi(); for(int64_t i=0;i<it*10;i++){ x=fe_mul(&x,&y); } t1=nowi();
  printf("F  scalar 5x51 fe_mul (serial):    %8.2f ns/field-mul  [%llu]\n",
     (double)(t1-t0)/(double)(it*10),(unsigned long long)x.l[0]); fflush(stdout);}

  if(stage==0||stage==7){
  static int64_t acc[31]; static uint16_t o16[16];
  for(int i=0;i<31;i++)acc[i]=i*1234567;
  carry16(acc,o16); t0=nowi(); for(int64_t i=0;i<it*10;i++){ acc[0]=o16[0]+i; carry16(acc,o16); } t1=nowi();
  printf("G  16-bit 31-col carry chain only: %8.2f ns  [%u]\n",
     (double)(t1-t0)/(double)(it*10),(unsigned)o16[3]); fflush(stdout);}
  return 0;
}
