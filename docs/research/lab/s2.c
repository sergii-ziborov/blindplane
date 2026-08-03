#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
static sigjmp_buf jb; static volatile const char* what;
static void h(int sig, siginfo_t *si, void *uc){
  ucontext_t *u = (ucontext_t*)uc;
  uint64_t pc = u->uc_mcontext->__ss.__pc;
  uint32_t insn = *(uint32_t*)pc;
  fprintf(stderr, "  SIGILL at pc=0x%llx insn=0x%08x  (during: %s)\n", pc, insn, what);
  siglongjmp(jb, 1);
}
#define TRY(name, code) do { what = name; if (sigsetjmp(jb,1)==0) { code; printf("  OK: %s\n", name); } } while(0)

int main(void){
  setbuf(stdout,NULL);
  struct sigaction sa; memset(&sa,0,sizeof sa);
  sa.sa_sigaction=h; sa.sa_flags=SA_SIGINFO; sigaction(SIGILL,&sa,NULL);

  TRY("smstart sm (enter streaming mode)", __asm__ volatile("smstart sm\n smstop sm"));
  TRY("smstart za (enable ZA)",            __asm__ volatile("smstart za\n smstop za"));
  TRY("smstart (both)",                    __asm__ volatile("smstart\n smstop"));
  TRY("rdsvl (non-streaming)",             { uint64_t v; __asm__ volatile("rdsvl %0, #1":"=r"(v)); printf("    rdsvl=%llu ",v); });
  TRY("mrs svcr",                          { uint64_t v; __asm__ volatile("mrs %0, SVCR":"=r"(v)); printf("    svcr=%llu ",v); });
  TRY("mrs ID_AA64SMFR0_EL1",              { uint64_t v; __asm__ volatile("mrs %0, S3_0_C0_C4_5":"=r"(v)); printf("    =%llx ",v); });
  return 0;
}
