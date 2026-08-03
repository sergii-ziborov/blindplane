#include <stdio.h>
#include <stdint.h>
#include <time.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
  return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}
#define CL "memory","cc","v8","v9","v10","v11","v12","v13","v14","v15"

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

/* ZA drain rate: N slices, no smopa, no zero. */
static void drain(int64_t iters,void*out,int nslice){
  __asm__ volatile("smstart\n\t"
   "1:\n\t mov w12,#0\n\t mov x9,%3\n\t"
   "2:\n\t str za[w12,0],[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t cmp w12,%w2\n\t blt 2b\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(iters):"r"(out),"r"(nslice),"r"(out):"x9","x12",CL);}

/* HONEST single field mul: 4 SMOPA into 4 d-tiles + drain those 4 tiles (32 slices).
   Still counts ZERO carry propagation / reduction / operand marshalling. */
static void honest_fieldmul(int64_t iters,const int16_t*a,const int16_t*b,void*out){
  __asm__ volatile("smstart\n\t ptrue p0.h\n\t"
   "1:\n\t"
   "ld1h {z0.h},p0/z,[%1]\n\t ld1h {z1.h},p0/z,[%2]\n\t"
   "ld1h {z2.h},p0/z,[%1]\n\t ld1h {z3.h},p0/z,[%2]\n\t"
   "zero {za}\n\t"
   "smopa za0.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za1.d,p0/m,p0/m,z0.h,z3.h\n\t"
   "smopa za2.d,p0/m,p0/m,z2.h,z1.h\n\t smopa za3.d,p0/m,p0/m,z2.h,z3.h\n\t"
   "mov w12,#0\n\t mov x9,%3\n\t"
   "2:\n\t str za[w12,0],[x9]\n\t add x9,x9,#64\n\t add w12,w12,#1\n\t cmp w12,#32\n\t blt 2b\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(iters):"r"(a),"r"(b),"r"(out):"z0","z1","z2","z3","p0","x9","x12",CL);}

/* scalar integer throughput OUTSIDE vs INSIDE streaming mode */
static uint64_t scalar_work(uint64_t n,uint64_t s){
  uint64_t a=s,b=s^0x9E37,c=s+7,d=s*3;
  for(uint64_t i=0;i<n;i++){ a=a*0x9E3779B97F4A7C15ull+1; b=b*0xC2B2AE3D27D4EB4Full+3;
                             c=c*0xD6E8FEB86659FD93ull+5; d=d*0xA24BAED4963EE407ull+7; }
  return a^b^c^d;
}
int main(void){
  static char buf[8192] __attribute__((aligned(256)));
  int16_t a[64],b[64]; for(int i=0;i<64;i++){a[i]=i+1;b[i]=2*i+1;}
  uint64_t t0,t1; int64_t it=1000000; double n;

  for(int ns=8; ns<=64; ns*=2){
    drain(1000,buf,ns); t0=nowi(); drain(it,buf,ns); t1=nowi();
    printf("ZA drain %2d slices (%4d B): %7.2f ns  -> %.2f ns/slice\n",
      ns,ns*64,(double)(t1-t0)/(double)it,(double)(t1-t0)/(double)it/ns);
  }
  honest_fieldmul(1000,a,b,buf); t0=nowi(); honest_fieldmul(it,a,b,buf); t1=nowi();
  printf("\nSME honest 1 field-mul (4 tiles, NO carry/reduce): %7.2f ns\n",(double)(t1-t0)/(double)it);

  /* scalar fe_mul: 4 INDEPENDENT chains = throughput, the fair match to a batched SME kernel */
  fe w={{1,2,3,4,5}},x={{6,7,8,9,10}},y={{11,12,13,14,15}},z={{16,17,18,19,20}};
  fe k={{0x7ffffffffffed,2,3,4,5}};
  for(int i=0;i<1000;i++){w=fe_mul(&w,&k);x=fe_mul(&x,&k);y=fe_mul(&y,&k);z=fe_mul(&z,&k);}
  t0=nowi(); for(int64_t i=0;i<it*2;i++){w=fe_mul(&w,&k);x=fe_mul(&x,&k);y=fe_mul(&y,&k);z=fe_mul(&z,&k);} t1=nowi();
  n=(double)(it*2*4);
  printf("scalar 5x51 fe_mul, 4 indep chains (throughput): %7.2f ns/field-mul [%llu]\n",
     (double)(t1-t0)/n,(unsigned long long)(w.l[0]^x.l[0]^y.l[0]^z.l[0]));

  /* scalar speed outside vs inside streaming mode */
  uint64_t r;
  scalar_work(100000,1); t0=nowi(); r=scalar_work(20000000,1); t1=nowi();
  double outns=(double)(t1-t0)/20000000.0;
  printf("\nscalar 4x MUL/iter, NORMAL mode:    %6.3f ns/iter [%llu]\n",outns,(unsigned long long)r);
  __asm__ volatile("smstart":::CL);
  t0=nowi(); r=scalar_work(20000000,1); t1=nowi();
  __asm__ volatile("smstop":::CL);
  double inns=(double)(t1-t0)/20000000.0;
  printf("scalar 4x MUL/iter, STREAMING mode: %6.3f ns/iter [%llu]  -> %.2fx %s\n",
     inns,(unsigned long long)r,inns/outns, inns>outns?"SLOWER":"faster");
  return 0;
}
