#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
  return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}

/* --- 1. cost of smstart/smstop round trip --- */
static void smpair(int64_t n){
  __asm__ volatile("1:\n\t smstart sm\n\t smstop sm\n\t subs %0,%0,#1\n\t bne 1b\n\t"
    :"+r"(n)::"memory","cc");
}
/* baseline empty loop */
static void emptyloop(int64_t n){
  __asm__ volatile("1:\n\t subs %0,%0,#1\n\t bne 1b\n\t":"+r"(n)::"cc");
}

/* --- 2. is NEON legal inside streaming mode? (FEAT_SME_FA64 absent) --- */
static sigjmp_buf jb; static volatile int trapped;
static void h(int s){(void)s; trapped=1; siglongjmp(jb,1);}
static void try_neon_in_streaming(void){
  trapped=0;
  if(sigsetjmp(jb,1)==0){
    __asm__ volatile("smstart sm\n\t"
                     "add v0.4s, v0.4s, v1.4s\n\t"   /* AdvSIMD inside streaming mode */
                     "smstop sm\n\t":::"v0","v1","memory");
  }
}
static void try_sve_in_streaming(void){
  trapped=0;
  if(sigsetjmp(jb,1)==0){
    __asm__ volatile("smstart sm\n\t add z0.s,z0.s,z1.s\n\t smstop sm\n\t":::"z0","z1","memory");
  }
}
/* --- 3. is XAR legal OUTSIDE streaming mode (i.e. plain SVE2)? --- */
static void try_sve_outside(void){
  trapped=0;
  if(sigsetjmp(jb,1)==0){ __asm__ volatile("add z0.s,z0.s,z1.s\n\t":::"z0","memory"); }
}
int main(void){
  signal(SIGILL,h); signal(SIGTRAP,h); signal(SIGBUS,h); signal(SIGSEGV,h);

  try_sve_outside();
  printf("SVE 'add z0.s' OUTSIDE streaming mode : %s\n", trapped?"ILLEGAL (traps) -> no non-streaming SVE on M4":"legal");
  try_sve_in_streaming();
  printf("SVE 'add z0.s' INSIDE  streaming mode : %s\n", trapped?"ILLEGAL (traps)":"legal");
  try_neon_in_streaming();
  printf("NEON 'add v0.4s' INSIDE streaming mode: %s\n", trapped?"ILLEGAL (traps) -> FA64 absent, no AdvSIMD in SM":"legal");

  int64_t n=2000000;
  smpair(1000); emptyloop(1000);
  uint64_t a=nowi(); smpair(n);     uint64_t b=nowi(); emptyloop(n); uint64_t c=nowi();
  double sm_ns=(double)(b-a)/n, mt_ns=(double)(c-b)/n;
  printf("\nsmstart+smstop pair: %.2f ns  (empty loop %.2f ns) -> ~%.2f ns net per transition pair\n",
         sm_ns, mt_ns, sm_ns-mt_ns);
  printf("At 3.0 GB/s NEON ChaCha, %.2f ns buys %.0f bytes of NEON work.\n", sm_ns-mt_ns, (sm_ns-mt_ns)*3.0);
  return 0;
}
