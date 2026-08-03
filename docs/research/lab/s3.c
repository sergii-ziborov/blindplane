#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
static sigjmp_buf jb; static volatile const char* what;
static void h(int s,siginfo_t*si,void*uc){ucontext_t*u=(ucontext_t*)uc;
  fprintf(stderr,"  SIGILL insn=0x%08x during %s\n",*(uint32_t*)u->uc_mcontext->__ss.__pc,what);siglongjmp(jb,1);}
#define TRY(n,c) do{what=n; if(sigsetjmp(jb,1)==0){c; printf("  OK: %s\n",n);} }while(0)
int main(void){ setbuf(stdout,NULL);
  struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_sigaction=h; sa.sa_flags=SA_SIGINFO; sigaction(SIGILL,&sa,NULL);
  // SVE instruction OUTSIDE streaming mode
  TRY("cntd outside streaming (needs FEAT_SVE)", {uint64_t v;__asm__ volatile("cntd %0":"=r"(v));printf("    cntd=%llu ",v);});
  // Same instruction INSIDE streaming mode
  TRY("cntd INSIDE streaming",{uint64_t v;__asm__ volatile("smstart sm\n cntd %0\n smstop sm":"=r"(v));printf("    cntd=%llu ",v);});
  return 0; }
