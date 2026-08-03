#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/sysctl.h>
static sigjmp_buf jb;
static void h(int s){ siglongjmp(jb,1); }
int main(void){
  int ok;
  signal(SIGILL,h); signal(SIGTRAP,h);
  // --- SVE probe: rdvl x0,#1  (0x04bf5020) ---
  if(sigsetjmp(jb,1)==0){
    unsigned long v;
    __asm__ volatile(".inst 0x04bf5020\n mov %0, x0":"=r"(v)::"x0");
    printf("SVE (rdvl):        EXECUTED, vector length = %lu bytes\n", v);
  } else printf("SVE (rdvl):        SIGILL  -> SVE NOT available to user code\n");
  // --- SME probe: smstart / smstop ---
  signal(SIGILL,h);
  if(sigsetjmp(jb,1)==0){
    __asm__ volatile(".inst 0xd503477f\n .inst 0xd503427f"); // smstart sm; smstop sm
    printf("SME (smstart/stop): EXECUTED -> SME streaming mode reachable\n");
  } else printf("SME (smstart/stop): SIGILL\n");
  // --- confirm AdvSIMD umull (32x32->64) exists; there is no 64x64->128 vector mul ---
  if(sigsetjmp(jb,1)==0){
    __asm__ volatile("umull v0.2d, v1.2s, v2.2s" ::: "v0");
    printf("NEON umull 32x32->64 (2 lanes): OK  (widest AdvSIMD integer multiply)\n");
  } else printf("NEON umull: SIGILL\n");
  (void)ok; return 0;
}
