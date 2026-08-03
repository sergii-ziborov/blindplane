#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
  return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}
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
volatile uint64_t sink;
int main(int argc,char**argv){
  pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0);
  uint64_t t0,t1; int64_t it=2000000;
  fe y={{0x3ffffffffffULL,0x3ffffffffffULL,0x123456789abULL,0x555555555ULL,0x1fffffffffULL}};
  /* scalar fe_mul at varying ILP width — find the real steady-state cost */
  for(int w=1;w<=8;w*=2){
    fe x[8]; for(int j=0;j<8;j++) for(int k=0;k<5;k++) x[j].l[k]=0x7ffffffffffULL-j-k;
    for(int j=0;j<w;j++) x[j]=fe_mul(&x[j],&y);
    t0=nowi();
    for(int64_t i=0;i<it;i++) for(int j=0;j<w;j++) x[j]=fe_mul(&x[j],&y);
    t1=nowi();
    uint64_t s=0; for(int j=0;j<w;j++)s^=x[j].l[0]; sink=s;
    printf("scalar fe_mul, %d independent chain(s): %6.2f ns/field-mul\n",
      w,(double)(t1-t0)/((double)it*w));
  }
  /* 16-bit limb carry propagation, 31 columns — mandatory after any SMOPA product */
  {
    static int64_t acc[31]; static uint16_t o16[16]; uint64_t s=0;
    for(int i=0;i<31;i++)acc[i]=(int64_t)i*1234567891LL;
    t0=nowi();
    for(int64_t i=0;i<it;i++){
      acc[0]=(int64_t)i; int64_t c=0;
      for(int k=0;k<31;k++){ int64_t v=acc[k]+c; o16[k&15]=(uint16_t)v; c=v>>16; }
      s+=o16[5];
    }
    t1=nowi(); sink=s;
    printf("\n16-bit 31-column carry chain (1 field mul): %6.2f ns\n",(double)(t1-t0)/(double)it);
  }
  /* 51-bit 5-column carry, what we do today */
  {
    static __uint128_t r[5]; static uint64_t o[5]; uint64_t s=0;
    for(int i=0;i<5;i++)r[i]=(__uint128_t)i*1234567891011ULL;
    t0=nowi();
    for(int64_t i=0;i<it;i++){
      r[0]=(__uint128_t)i; uint64_t c=0;
      for(int k=0;k<5;k++){ __uint128_t v=r[k]+c; o[k]=(uint64_t)v&M51; c=(uint64_t)(v>>51); }
      o[0]+=c*19; s+=o[2];
    }
    t1=nowi(); sink=s;
    printf("51-bit  5-column carry chain (1 field mul): %6.2f ns\n",(double)(t1-t0)/(double)it);
  }
  return 0;
}
