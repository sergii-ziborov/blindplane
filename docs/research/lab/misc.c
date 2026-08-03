#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
  return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}
#define CL "memory","cc","v8","v9","v10","v11","v12","v13","v14","v15"
static sigjmp_buf jb; static void h(int s){(void)s; siglongjmp(jb,1);}

static volatile int go=0; static int64_t ITER=3000000;
static void*worker(void*arg){
  (void)arg; int16_t a[64],b[64]; for(int i=0;i<64;i++){a[i]=i+1;b[i]=2*i+1;}
  while(!go){}
  int64_t it=ITER;
  __asm__ volatile("smstart\n\t ptrue p0.h\n\t zero {za}\n\t"
   "ld1h {z0.h},p0/z,[%1]\n\t ld1h {z1.h},p0/z,[%2]\n\t"
   "1:\n\t smopa za0.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za1.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "smopa za2.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za3.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "smopa za4.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za5.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "smopa za6.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za7.d,p0/m,p0/m,z0.h,z1.h\n\t"
   "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t"
   :"+r"(it):"r"(a),"r"(b):"z0","z1","p0",CL);
  return 0;
}
int main(void){
  /* 1. Is NEON legal in streaming mode? */
  signal(SIGILL,h);
  if(sigsetjmp(jb,1)==0){
    __asm__ volatile("smstart\n\t add v0.4s,v0.4s,v0.4s\n\t smstop":::"v0",CL);
    printf("NEON (add v0.4s) inside streaming mode: LEGAL\n");
  } else printf("NEON (add v0.4s) inside streaming mode: SIGILL -- NEON UNAVAILABLE\n");
  signal(SIGILL,SIG_DFL);

  /* 2. SMOPA scaling across threads: is the SME unit per-core or shared? */
  for(int nt=1; nt<=8; nt*=2){
    pthread_t th[8]; go=0;
    for(int i=0;i<nt;i++) pthread_create(&th[i],0,worker,0);
    struct timespec ts={0,200000000}; nanosleep(&ts,0);
    uint64_t t0=nowi(); go=1;
    for(int i=0;i<nt;i++) pthread_join(th[i],0);
    uint64_t t1=nowi();
    double tot=(double)nt*(double)ITER*8.0;           /* total SMOPAs */
    printf("SMOPA threads=%d: %7.3f ns/SMOPA-per-thread, aggregate %.1f G int16MAC/s\n",
      nt,(double)(t1-t0)/((double)ITER*8.0), tot*256.0/(double)(t1-t0));
  }
  return 0;
}
