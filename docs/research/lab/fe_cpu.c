#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#define MASK51 0x7ffffffffffffULL
typedef unsigned __int128 u128;
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}

static void fe_mul(uint64_t*h,const uint64_t*a,const uint64_t*b){
  u128 b1=(u128)b[1]*19,b2=(u128)b[2]*19,b3=(u128)b[3]*19,b4=(u128)b[4]*19;
  u128 a0=a[0],a1=a[1],a2=a[2],a3=a[3],a4=a[4];
  u128 B0=b[0],B1=b[1],B2=b[2],B3=b[3],B4=b[4];
  u128 r[5];
  r[0]=a0*B0+a1*b4+a2*b3+a3*b2+a4*b1;
  r[1]=a0*B1+a1*B0+a2*b4+a3*b3+a4*b2;
  r[2]=a0*B2+a1*B1+a2*B0+a3*b4+a4*b3;
  r[3]=a0*B3+a1*B2+a2*B1+a3*B0+a4*b4;
  r[4]=a0*B4+a1*B3+a2*B2+a3*B1+a4*B0;
  uint64_t c;
  c=(uint64_t)(r[0]>>51); h[0]=(uint64_t)r[0]&MASK51; r[1]+=c;
  c=(uint64_t)(r[1]>>51); h[1]=(uint64_t)r[1]&MASK51; r[2]+=c;
  c=(uint64_t)(r[2]>>51); h[2]=(uint64_t)r[2]&MASK51; r[3]+=c;
  c=(uint64_t)(r[3]>>51); h[3]=(uint64_t)r[3]&MASK51; r[4]+=c;
  c=(uint64_t)(r[4]>>51); h[4]=(uint64_t)r[4]&MASK51;
  h[0]+=c*19; h[1]+=h[0]>>51; h[0]&=MASK51;
}
static uint64_t chain(uint64_t gid,uint64_t iters){
  uint64_t x[5]={gid+1,2,3,4,5},t[5];
  const uint64_t k[5]={0x1234567891234ULL,0x2345678912345ULL,0x3456789123456ULL,0x4567891234567ULL,0x5678912345678ULL};
  for(uint64_t i=0;i<iters;++i){fe_mul(t,x,k);for(int j=0;j<5;j++)x[j]=t[j];}
  return x[0]^x[1]^x[2]^x[3]^x[4];
}
typedef struct{uint64_t g,it,out;}arg_t;
static void*w(void*p){arg_t*a=p;a->out=chain(a->g,a->it);return NULL;}
int main(void){
  printf("cpu fe_mul checksum lane0..3: %016llx %016llx %016llx %016llx\n",
    (unsigned long long)chain(0,1),(unsigned long long)chain(1,1),
    (unsigned long long)chain(2,1),(unsigned long long)chain(3,1));
  uint64_t iters=30000000ULL;
  double t0=now(); volatile uint64_t r=chain(0,iters); double t1=now(); (void)r;
  printf("CPU fe_mul  1 core : %.3f s -> %.2f M fe_mul/s\n",t1-t0,iters/(t1-t0)/1e6);
  int nt=10; pthread_t th[16]; arg_t ar[16];
  for(int i=0;i<nt;i++){ar[i].g=i;ar[i].it=iters;}
  double s=now();
  for(int i=0;i<nt;i++)pthread_create(&th[i],NULL,w,&ar[i]);
  for(int i=0;i<nt;i++)pthread_join(th[i],NULL);
  double e=now();
  printf("CPU fe_mul 10 cores: %.3f s -> %.2f M fe_mul/s\n",e-s,(double)iters*nt/(e-s)/1e6);
  return 0;
}
