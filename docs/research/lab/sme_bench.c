#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <arm_sve.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}

__attribute__((target("sme2"))) __arm_locally_streaming
static uint64_t sme_loop(uint64_t iters){
  svbool_t pg=svptrue_b64();
  svuint64_t a0=svindex_u64(1,2),a1=svindex_u64(3,2),a2=svindex_u64(5,2),a3=svindex_u64(7,2);
  svuint64_t b0=svdup_u64(0x9E3779B97F4A7C15ULL),b1=svdup_u64(0xC2B2AE3D27D4EB4FULL);
  svuint64_t s0=svdup_u64(0),s1=svdup_u64(0),s2=svdup_u64(0),s3=svdup_u64(0);
  for(uint64_t t=0;t<iters;++t){
    s0=svadd_u64_x(pg,s0,svmulh_u64_x(pg,a0,b0)); a0=svadd_u64_x(pg,svmul_u64_x(pg,a0,b1),svdup_u64(1));
    s1=svadd_u64_x(pg,s1,svmulh_u64_x(pg,a1,b0)); a1=svadd_u64_x(pg,svmul_u64_x(pg,a1,b1),svdup_u64(1));
    s2=svadd_u64_x(pg,s2,svmulh_u64_x(pg,a2,b0)); a2=svadd_u64_x(pg,svmul_u64_x(pg,a2,b1),svdup_u64(1));
    s3=svadd_u64_x(pg,s3,svmulh_u64_x(pg,a3,b0)); a3=svadd_u64_x(pg,svmul_u64_x(pg,a3,b1),svdup_u64(1));
  }
  return svaddv_u64(pg,sveor_u64_x(pg,sveor_u64_x(pg,s0,s1),sveor_u64_x(pg,s2,s3)));
}
__attribute__((target("sme2"))) __arm_locally_streaming
static uint64_t svl_bytes(void){ return svcntb(); }

int main(void){
  printf("streaming vector length: %llu bytes (%llu x u64 lanes)\n",
    (unsigned long long)svl_bytes(), (unsigned long long)svl_bytes()/8);
  uint64_t lanes = svl_bytes()/8;
  uint64_t iters = 20000000ULL;
  volatile uint64_t r = sme_loop(1000); (void)r;   // warm
  double t0=now(); volatile uint64_t x=sme_loop(iters); double t1=now(); (void)x;
  // per iter: 4 mulh + 4 mul = 8 vector multiplies, each of `lanes` 64-bit multiplies
  double muls=(double)iters*8.0*(double)lanes;
  printf("SME streaming-SVE 1 core: %.3f s -> %.2f G 64x64 multiplies/s\n", t1-t0, muls/(t1-t0)/1e9);
  return 0;
}
