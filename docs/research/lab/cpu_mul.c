#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <stdlib.h>

static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }

// identical shape to the Metal kernel: 4 mulhi + 4 mullo per iteration
static uint64_t loop64(uint64_t seed, uint64_t iters){
  uint64_t a0=seed+1,a1=seed+3,a2=seed+5,a3=seed+7;
  uint64_t b0=0x9E3779B97F4A7C15ULL,b1=0xC2B2AE3D27D4EB4FULL;
  uint64_t s0=0,s1=0,s2=0,s3=0;
  for(uint64_t t=0;t<iters;++t){
    s0+=(uint64_t)(((__uint128_t)a0*b0)>>64); a0=a0*b1+1;
    s1+=(uint64_t)(((__uint128_t)a1*b0)>>64); a1=a1*b1+1;
    s2+=(uint64_t)(((__uint128_t)a2*b0)>>64); a2=a2*b1+1;
    s3+=(uint64_t)(((__uint128_t)a3*b0)>>64); a3=a3*b1+1;
  }
  return s0^s1^s2^s3;
}
typedef struct { uint64_t seed, iters, out; } arg_t;
static void* worker(void* p){ arg_t* a=p; a->out=loop64(a->seed,a->iters); return NULL; }

int main(int argc,char**argv){
  uint64_t iters = 200000000ULL; // 200M iters = 1.6G multiplies per thread
  // single core
  double t0=now(); volatile uint64_t r=loop64(12345,iters); double t1=now();
  double muls = (double)iters*8.0;
  printf("CPU 1 core : %.3f s, %.2f G multiplies/s  (sink %llu)\n", t1-t0, muls/(t1-t0)/1e9,(unsigned long long)r);

  for (int nt=10; nt<=10; nt++){
    pthread_t th[16]; arg_t ar[16];
    for(int i=0;i<nt;i++){ ar[i].seed=i*7+1; ar[i].iters=iters; }
    double s=now();
    for(int i=0;i<nt;i++) pthread_create(&th[i],NULL,worker,&ar[i]);
    uint64_t acc=0;
    for(int i=0;i<nt;i++){ pthread_join(th[i],NULL); acc^=ar[i].out; }
    double e=now();
    printf("CPU %2d core: %.3f s, %.2f G multiplies/s  (sink %llu)\n", nt, e-s, muls*nt/(e-s)/1e9,(unsigned long long)acc);
  }
  return 0;
}
