#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#define MASK51 0x7ffffffffffffULL
typedef unsigned __int128 u128;
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
static void carry5(uint64_t*h,u128*r){
  uint64_t c;
  c=(uint64_t)(r[0]>>51);h[0]=(uint64_t)r[0]&MASK51;r[1]+=c;
  c=(uint64_t)(r[1]>>51);h[1]=(uint64_t)r[1]&MASK51;r[2]+=c;
  c=(uint64_t)(r[2]>>51);h[2]=(uint64_t)r[2]&MASK51;r[3]+=c;
  c=(uint64_t)(r[3]>>51);h[3]=(uint64_t)r[3]&MASK51;r[4]+=c;
  c=(uint64_t)(r[4]>>51);h[4]=(uint64_t)r[4]&MASK51;
  h[0]+=c*19;h[1]+=h[0]>>51;h[0]&=MASK51;}
static void fe_mul(uint64_t*h,const uint64_t*a,const uint64_t*b){
  u128 B1=(u128)b[1]*19,B2=(u128)b[2]*19,B3=(u128)b[3]*19,B4=(u128)b[4]*19;
  u128 a0=a[0],a1=a[1],a2=a[2],a3=a[3],a4=a[4];
  u128 b0=b[0],b1=b[1],b2=b[2],b3=b[3],b4=b[4];
  u128 r[5];
  r[0]=a0*b0+a1*B4+a2*B3+a3*B2+a4*B1;
  r[1]=a0*b1+a1*b0+a2*B4+a3*B3+a4*B2;
  r[2]=a0*b2+a1*b1+a2*b0+a3*B4+a4*B3;
  r[3]=a0*b3+a1*b2+a2*b1+a3*b0+a4*B4;
  r[4]=a0*b4+a1*b3+a2*b2+a3*b1+a4*b0;
  carry5(h,r);}
static void fe_sq(uint64_t*h,const uint64_t*a){
  uint64_t a0_2=2*a[0],a1_2=2*a[1],a3_19=19*a[3],a4_19=19*a[4];
  u128 r[5];
  r[0]=(u128)a[0]*a[0]+(u128)a1_2*a4_19+(u128)(2*a[2])*a3_19;
  r[1]=(u128)a0_2*a[1]+(u128)(2*a[2])*a4_19+(u128)a[3]*a3_19;
  r[2]=(u128)a0_2*a[2]+(u128)a[1]*a[1]+(u128)(2*a[3])*a4_19;
  r[3]=(u128)a0_2*a[3]+(u128)a1_2*a[2]+(u128)a[4]*a4_19;
  r[4]=(u128)a0_2*a[4]+(u128)a1_2*a[3]+(u128)a[2]*a[2];
  carry5(h,r);}
static void fe_add(uint64_t*h,const uint64_t*f,const uint64_t*g){for(int i=0;i<5;i++)h[i]=f[i]+g[i];}
static void fe_sub(uint64_t*h,const uint64_t*f,const uint64_t*g){
  h[0]=(f[0]+0xFFFFFFFFFFFDAULL)-g[0];
  for(int i=1;i<5;i++)h[i]=(f[i]+0xFFFFFFFFFFFFEULL)-g[i];}
static void fe_m121666(uint64_t*h,const uint64_t*f){u128 r[5];for(int i=0;i<5;i++)r[i]=(u128)f[i]*121666ULL;carry5(h,r);}
static void cswap(uint64_t*a,uint64_t*b,uint64_t bit){uint64_t m=0ULL-bit;for(int i=0;i<5;i++){uint64_t t=m&(a[i]^b[i]);a[i]^=t;b[i]^=t;}}
static uint64_t one_ladder(uint64_t gid,uint64_t r){
  uint64_t x1[5]={gid+r+9,2,3,4,5};
  uint64_t x2[5]={1,0,0,0,0},z2[5]={0,0,0,0,0};
  uint64_t x3[5]={x1[0],x1[1],x1[2],x1[3],x1[4]},z3[5]={1,0,0,0,0};
  uint64_t sc=0x5A5A5A5A5A5A5A5AULL^gid, swap=0;
  uint64_t a[5],b[5],aa[5],bb[5],e[5],c[5],d[5],da[5],cb[5],t[5];
  for(int pos=254;pos>=0;--pos){
    uint64_t bit=(sc>>(pos&63))&1;
    swap^=bit;cswap(x2,x3,swap);cswap(z2,z3,swap);swap=bit;
    fe_add(a,x2,z2);fe_sq(aa,a);
    fe_sub(b,x2,z2);fe_sq(bb,b);
    fe_sub(e,aa,bb);
    fe_add(c,x3,z3);fe_sub(d,x3,z3);
    fe_mul(da,d,a);fe_mul(cb,c,b);
    fe_add(t,da,cb);fe_sq(x3,t);
    fe_sub(t,da,cb);fe_sq(t,t);fe_mul(z3,x1,t);
    fe_mul(x2,aa,bb);
    fe_m121666(t,e);fe_add(t,t,bb);fe_mul(z2,e,t);
  }
  cswap(x2,x3,swap);cswap(z2,z3,swap);
  uint64_t inv[5]={z2[0],z2[1],z2[2],z2[3],z2[4]};
  for(int i=0;i<254;i++)fe_sq(inv,inv);
  for(int i=0;i<11;i++)fe_mul(inv,inv,z2);
  fe_mul(t,x2,inv);
  return t[0]^t[1]^t[2]^t[3]^t[4];
}
typedef struct{uint64_t g,n,out;}arg_t;
static void*w(void*p){arg_t*a=p;uint64_t acc=0;for(uint64_t i=0;i<a->n;i++)acc^=one_ladder(a->g,i);a->out=acc;return NULL;}
int main(void){
  uint64_t n=4000;
  double t0=now();uint64_t acc=0;for(uint64_t i=0;i<n;i++)acc^=one_ladder(0,i);double t1=now();
  printf("CPU ladder  1 core : %.3f s -> %.0f ops/s (sink %llx)\n",t1-t0,n/(t1-t0),(unsigned long long)acc);
  int nt=10;pthread_t th[16];arg_t ar[16];
  for(int i=0;i<nt;i++){ar[i].g=i;ar[i].n=n;}
  double s=now();
  for(int i=0;i<nt;i++)pthread_create(&th[i],NULL,w,&ar[i]);
  for(int i=0;i<nt;i++)pthread_join(th[i],NULL);
  double e=now();
  printf("CPU ladder 10 cores: %.3f s -> %.0f ops/s\n",e-s,(double)n*nt/(e-s));
  return 0;
}
