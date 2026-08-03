#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
  return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}
#define CL "memory","cc","v8","v9","v10","v11","v12","v13","v14","v15"
#define ARCH ".arch armv9-a+sme2+sme-i16i64\n\t"

/* REALISTIC batch-8: 8 DISTINCT operand pairs loaded from memory,
   8 SMOPAs into za0..za7, one bulk STR ZA drain of all 64 slices. */
static void batch8_real(int64_t iters,const int16_t*ab,void*out){
  __asm__ volatile(ARCH "smstart\n\t ptrue p0.h\n\t"
   "1:\n\t mov x10,%1\n\t zero {za}\n\t"
   "ld1h {z0.h},p0/z,[x10]\n\t add x10,x10,#64\n\t ld1h {z1.h},p0/z,[x10]\n\t add x10,x10,#64\n\t"
   "smopa za0.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "ld1h {z0.h},p0/z,[x10]\n\t add x10,x10,#64\n\t ld1h {z1.h},p0/z,[x10]\n\t add x10,x10,#64\n\t"
   "smopa za1.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "ld1h {z0.h},p0/z,[x10]\n\t add x10,x10,#64\n\t ld1h {z1.h},p0/z,[x10]\n\t add x10,x10,#64\n\t"
   "smopa za2.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "ld1h {z0.h},p0/z,[x10]\n\t add x10,x10,#64\n\t ld1h {z1.h},p0/z,[x10]\n\t add x10,x10,#64\n\t"
   "smopa za3.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "ld1h {z0.h},p0/z,[x10]\n\t add x10,x10,#64\n\t ld1h {z1.h},p0/z,[x10]\n\t add x10,x10,#64\n\t"
   "smopa za4.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "ld1h {z0.h},p0/z,[x10]\n\t add x10,x10,#64\n\t ld1h {z1.h},p0/z,[x10]\n\t add x10,x10,#64\n\t"
   "smopa za5.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "ld1h {z0.h},p0/z,[x10]\n\t add x10,x10,#64\n\t ld1h {z1.h},p0/z,[x10]\n\t add x10,x10,#64\n\t"
   "smopa za6.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "ld1h {z0.h},p0/z,[x10]\n\t add x10,x10,#64\n\t ld1h {z1.h},p0/z,[x10]\n\t"
   "smopa za7.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "mov w12,#0\n\t mov x9,%2\n\t"
   "2:\n\t str za[w12,0],[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t cmp w12,#64\n\t blt 2b\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(iters):"r"(ab),"r"(out):"z0","z1","p0","x9","x10","x12",CL);}

/* SMOPA-only, for multicore contention test */
static void smopa_only(int64_t iters,const int16_t*a,const int16_t*b){
  __asm__ volatile(ARCH "smstart\n\t ptrue p0.h\n\t zero {za}\n\t"
   "ld1h {z0.h},p0/z,[%1]\n\t ld1h {z1.h},p0/z,[%2]\n\t"
   "1:\n\t"
   "smopa za0.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za1.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "smopa za2.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za3.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "smopa za4.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za5.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "smopa za6.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za7.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(iters):"r"(a),"r"(b):"z0","z1","p0",CL);}

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
/* convert 5x51 -> 16x16-bit limbs (needed to feed SMOPA), constant time */
static inline void fe_to16(const fe*x,int16_t*o){
  uint8_t t[32]; uint64_t l;
  for(int i=0;i<5;i++){ l=x->l[i]; for(int j=0;j<8;j++) t[(i*51+j*8)/8 % 32] = (uint8_t)(l>>(j*8)); }
  for(int i=0;i<16;i++) o[i] = (int16_t)(t[2*i] | ((uint16_t)t[2*i+1]<<8)) & 0x7fff;
}
static void*thr(void*p){
  int64_t it=*(int64_t*)p; int16_t a[32],b[32];
  for(int i=0;i<32;i++){a[i]=i+1;b[i]=2*i+1;}
  smopa_only(it,a,b); return 0;
}
int main(int argc,char**argv){
  int stage = argc>1 ? atoi(argv[1]) : 0;
  pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0);
  static int16_t ab[8*2*32] __attribute__((aligned(256)));
  static char buf[8192] __attribute__((aligned(256)));
  for(int i=0;i<8*2*32;i++) ab[i]=(i*7+1)&0x7fff;
  uint64_t t0,t1; double n; int64_t it=1000000;

  if(stage==1){
    batch8_real(100,ab,buf); t0=nowi(); batch8_real(it/8,ab,buf); t1=nowi(); n=(double)(it/8);
    printf("B' realistic batch-8 (8 distinct operand pairs + bulk drain):\n");
    printf("     %8.2f ns/batch = %7.2f ns/field-mul (multiply stage only)\n",
      (double)(t1-t0)/n,(double)(t1-t0)/n/8.0);
  }
  if(stage==2){
    /* fair scalar: 8 INDEPENDENT chains -> full ILP, same independence SME batch assumes */
    fe x[8],y[8];
    for(int j=0;j<8;j++){ for(int k=0;k<5;k++){x[j].l[k]=0x7ffffffffffULL-j*k-k;y[j].l[k]=0x3ffffffffffULL+j+k;} }
    for(int j=0;j<8;j++) x[j]=fe_mul(&x[j],&y[j]);
    t0=nowi();
    for(int64_t i=0;i<it;i++){ for(int j=0;j<8;j++) x[j]=fe_mul(&x[j],&y[j]); }
    t1=nowi(); n=(double)it*8;
    uint64_t s=0; for(int j=0;j<8;j++)s^=x[j].l[0];
    printf("F' scalar 5x51 fe_mul, 8 independent chains (full ILP):\n");
    printf("     %8.2f ns/field-mul  [%llu]\n",(double)(t1-t0)/n,(unsigned long long)s);
  }
  if(stage==3){
    /* limb conversion cost that SME path must pay on every operand */
    fe x={{0x7ffffffffffULL,0x7ffffffffffULL,0x123456789abULL,0x555555555ULL,0x1fffffffffULL}};
    int16_t o[16]; fe_to16(&x,o);
    t0=nowi(); for(int64_t i=0;i<it*5;i++){ x.l[0]+=i; fe_to16(&x,o); } t1=nowi();
    printf("H  5x51 -> 16x16 limb conversion: %7.2f ns per operand [%d]\n",
      (double)(t1-t0)/(double)(it*5),(int)o[2]);
  }
  if(stage==4){
    /* multicore SME contention: is the ZA/SMOPA unit shared per cluster? */
    printf("SME multicore scaling (SMOPA-only, 8 per iter):\n");
    for(int nt=1;nt<=8;nt*=2){
      pthread_t th[8]; int64_t per=it/2;
      t0=nowi();
      for(int i=0;i<nt;i++) pthread_create(&th[i],0,thr,&per);
      for(int i=0;i<nt;i++) pthread_join(th[i],0);
      t1=nowi();
      double tot=(double)nt*per*8;
      printf("   %d thread(s): %8.3f ns/SMOPA effective, aggregate %.1f G int16 MAC/s\n",
        nt, (double)(t1-t0)/tot, tot*256/(double)(t1-t0));
    }
  }
  return 0;
}
