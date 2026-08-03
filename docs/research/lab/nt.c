#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
static void h(int s,siginfo_t*si,void*uc){ ucontext_t*u=(ucontext_t*)uc;
  uint32_t insn=*(uint32_t*)u->uc_mcontext->__ss.__pc;
  char b[128]; int n=snprintf(b,sizeof b,"ILLEGAL (insn=0x%08x)\n",insn);
  write(2,b,n); _exit(4); }
int main(int argc,char**argv){ setbuf(stdout,NULL);
  struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_sigaction=h; sa.sa_flags=SA_SIGINFO; sigaction(SIGILL,&sa,NULL);
  switch(atoi(argv[1])){
   case 0: __asm__ volatile("smstart sm\n add v0.16b, v0.16b, v0.16b\n smstop sm":::"v0"); puts("OK"); break;
   case 1: __asm__ volatile("smstart sm\n aese v0.16b, v1.16b\n smstop sm":::"v0","v1"); puts("OK"); break;
   case 2: __asm__ volatile("smstart sm\n pmull v0.1q, v1.1d, v2.1d\n smstop sm":::"v0","v1","v2"); puts("OK"); break;
   case 3: __asm__ volatile("smstart sm\n sha256h q0, q1, v2.4s\n smstop sm":::"v0","v1","v2"); puts("OK"); break;
   case 4: __asm__ volatile("smstart sm\n tbl v0.16b, {v1.16b}, v2.16b\n smstop sm":::"v0","v1","v2"); puts("OK"); break;
   case 5: __asm__ volatile("smstart sm\n rev64 v0.4s, v1.4s\n smstop sm":::"v0","v1"); puts("OK"); break;
   case 6: __asm__ volatile("smstart sm\n ext v0.16b, v1.16b, v2.16b, #4\n smstop sm":::"v0","v1","v2"); puts("OK"); break;
   case 7: __asm__ volatile("smstart sm\n eor3 v0.16b, v1.16b, v2.16b, v3.16b\n smstop sm":::"v0","v1","v2","v3"); puts("OK"); break;
  }
  return 0; }
