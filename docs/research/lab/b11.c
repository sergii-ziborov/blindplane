#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}
#define CL "memory","cc","v8","v9","v10","v11","v12","v13","v14","v15"
static void sve_xar(int64_t it){
 __asm__ volatile("smstart sm\n\t"
  "1:\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#16\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#20\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#24\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#25\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#16\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#20\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#24\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#25\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#16\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#20\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#24\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#25\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#16\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#20\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#24\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#25\n\t"
  "subs %0,%0,#1\n\t bne 1b\n\t smstop sm\n\t":"+r"(it)::
  "z0","z1","z2","z3","z4","z5","z6","z7","z8","z9","z10","z11","z12","z13","z14","z15",CL);}
static void neon_qr(int64_t it){
 __asm__ volatile("1:\n\t"
  "add v0.4s,v0.4s,v1.4s\n\t eor v3.16b,v3.16b,v0.16b\n\t rev32 v3.8h,v3.8h\n\t"
  "add v2.4s,v2.4s,v3.4s\n\t eor v20.16b,v1.16b,v2.16b\n\t shl v1.4s,v20.4s,#12\n\t usra v1.4s,v20.4s,#20\n\t"
  "add v0.4s,v0.4s,v1.4s\n\t eor v20.16b,v3.16b,v0.16b\n\t shl v3.4s,v20.4s,#8\n\t usra v3.4s,v20.4s,#24\n\t"
  "add v2.4s,v2.4s,v3.4s\n\t eor v20.16b,v1.16b,v2.16b\n\t shl v1.4s,v20.4s,#7\n\t usra v1.4s,v20.4s,#25\n\t"
  "add v4.4s,v4.4s,v5.4s\n\t eor v7.16b,v7.16b,v4.16b\n\t rev32 v7.8h,v7.8h\n\t"
  "add v6.4s,v6.4s,v7.4s\n\t eor v21.16b,v5.16b,v6.16b\n\t shl v5.4s,v21.4s,#12\n\t usra v5.4s,v21.4s,#20\n\t"
  "add v4.4s,v4.4s,v5.4s\n\t eor v21.16b,v7.16b,v4.16b\n\t shl v7.4s,v21.4s,#8\n\t usra v7.4s,v21.4s,#24\n\t"
  "add v6.4s,v6.4s,v7.4s\n\t eor v21.16b,v5.16b,v6.16b\n\t shl v5.4s,v21.4s,#7\n\t usra v5.4s,v21.4s,#25\n\t"
  "add v8.4s,v8.4s,v9.4s\n\t eor v11.16b,v11.16b,v8.16b\n\t rev32 v11.8h,v11.8h\n\t"
  "add v10.4s,v10.4s,v11.4s\n\t eor v22.16b,v9.16b,v10.16b\n\t shl v9.4s,v22.4s,#12\n\t usra v9.4s,v22.4s,#20\n\t"
  "add v8.4s,v8.4s,v9.4s\n\t eor v22.16b,v11.16b,v8.16b\n\t shl v11.4s,v22.4s,#8\n\t usra v11.4s,v22.4s,#24\n\t"
  "add v10.4s,v10.4s,v11.4s\n\t eor v22.16b,v9.16b,v10.16b\n\t shl v9.4s,v22.4s,#7\n\t usra v9.4s,v22.4s,#25\n\t"
  "add v12.4s,v12.4s,v13.4s\n\t eor v15.16b,v15.16b,v12.16b\n\t rev32 v15.8h,v15.8h\n\t"
  "add v14.4s,v14.4s,v15.4s\n\t eor v23.16b,v13.16b,v14.16b\n\t shl v13.4s,v23.4s,#12\n\t usra v13.4s,v23.4s,#20\n\t"
  "add v12.4s,v12.4s,v13.4s\n\t eor v23.16b,v15.16b,v12.16b\n\t shl v15.4s,v23.4s,#8\n\t usra v15.4s,v23.4s,#24\n\t"
  "add v14.4s,v14.4s,v15.4s\n\t eor v23.16b,v13.16b,v14.16b\n\t shl v13.4s,v23.4s,#7\n\t usra v13.4s,v23.4s,#25\n\t"
  "subs %0,%0,#1\n\t bne 1b\n\t":"+r"(it)::
  "v0","v1","v2","v3","v4","v5","v6","v7","v8","v9","v10","v11","v12","v13","v14","v15",
  "v20","v21","v22","v23","memory","cc");}

static int64_t ITERS;
static void* w_sve(void*a){(void)a; sve_xar(ITERS); return 0;}
static void* w_neon(void*a){(void)a; neon_qr(ITERS); return 0;}
static double hybrid(int nsve,int nneon,int64_t iters){
  ITERS=iters; pthread_t t[24]; int k=0; uint64_t t0=nowi();
  for(int i=0;i<nsve;i++) pthread_create(&t[k++],0,w_sve,0);
  for(int i=0;i<nneon;i++) pthread_create(&t[k++],0,w_neon,0);
  for(int i=0;i<k;i++) pthread_join(t[i],0);
  uint64_t t1=nowi();
  double qr = (8.0*16*nsve + 8.0*4*nneon)*(double)iters;
  return qr/80.0*64.0/(double)(t1-t0);
}
/* memory bandwidth: read+write streaming */
static double membw(size_t bytes,int nthr);
#include <sys/mman.h>
static size_t MB_N; static char *MB_SRC,*MB_DST; static int MB_T;
static void* mbw(void*a){ long id=(long)a; size_t per=MB_N/MB_T;
  memcpy(MB_DST+id*per, MB_SRC+id*per, per); return 0;}
static double membw(size_t bytes,int nthr){
  MB_N=bytes; MB_T=nthr;
  MB_SRC=mmap(0,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  MB_DST=mmap(0,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  memset(MB_SRC,1,bytes); memset(MB_DST,2,bytes);
  pthread_t t[16]; uint64_t t0=nowi();
  for(int r=0;r<5;r++){ for(long i=0;i<nthr;i++) pthread_create(&t[i],0,mbw,(void*)i);
    for(int i=0;i<nthr;i++) pthread_join(t[i],0); }
  uint64_t t1=nowi();
  double gb = (double)bytes*5*2/(double)(t1-t0); /* read+write */
  munmap(MB_SRC,bytes); munmap(MB_DST,bytes); return gb;
}
int main(void){
  int64_t it=3000000;
  printf("HYBRID: N threads on SME streaming-SVE + M threads on NEON (aggregate ChaCha20 GB/s)\n");
  printf(" sve+neon |  GB/s\n");
  int cfg[][2]={{1,0},{0,9},{1,9},{2,8},{1,8},{2,7},{4,6},{1,6},{3,7},{4,5},{0,10},{2,9}};
  for(unsigned i=0;i<sizeof(cfg)/sizeof(cfg[0]);i++){
    double g=hybrid(cfg[i][0],cfg[i][1],it);
    printf("   %d + %-2d  | %6.2f\n",cfg[i][0],cfg[i][1],g);
  }
  printf("\nMEMORY BANDWIDTH (memcpy, read+write counted):\n");
  for(int n=1;n<=10;n+=(n<4?1:3)) printf("  %2d threads, 256MB: %6.1f GB/s\n",n,membw(256ull<<20,n));
  return 0;
}
