#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}
#define CL "memory","cc","v8","v9","v10","v11","v12","v13","v14","v15"
static int probe(const char*n,void(*f)(void)){fflush(stdout);pid_t p=fork();if(!p){f();_exit(0);}int st;waitpid(p,&st,0);
 int ok=WIFEXITED(st)&&!WEXITSTATUS(st);printf("  %-34s %s\n",n,ok?"OK":"SIGILL/fail");return ok;}
static void f_xar(void){__asm__ volatile("smstart sm\n\t xar z0.s,z0.s,z1.s,#25\n\t smstop sm":::"z0",CL);}
static void f_eor3(void){__asm__ volatile("smstart sm\n\t eor3 z0.d,z0.d,z1.d,z2.d\n\t smstop sm":::"z0",CL);}
static void f_aese(void){__asm__ volatile("smstart sm\n\t aese z0.b,z0.b,z1.b\n\t smstop sm":::"z0",CL);}
static void f_pmullb(void){__asm__ volatile("smstart sm\n\t pmullb z0.q,z1.d,z2.d\n\t smstop sm":::"z0",CL);}
static void f_sha3(void){__asm__ volatile("smstart sm\n\t rax1 z0.d,z1.d,z2.d\n\t smstop sm":::"z0",CL);}
static void f_mul64(void){__asm__ volatile("smstart sm\n\t mul z0.d,z1.d,z2.d\n\t smstop sm":::"z0",CL);}
static void f_umulh(void){__asm__ volatile("smstart sm\n\t umulh z0.d,z1.d,z2.d\n\t smstop sm":::"z0",CL);}
static void f_tbl(void){__asm__ volatile("smstart sm\n\t tbl z0.b,{z1.b},z2.b\n\t smstop sm":::"z0",CL);}
int main(void){
  printf("streaming-mode instruction availability on M4:\n");
  probe("SVE2 XAR (xor+rotate)",f_xar);
  probe("SVE2 EOR3",f_eor3);
  probe("SVE-AES AESE",f_aese);
  probe("SVE2 PMULLB (128b carryless)",f_pmullb);
  probe("SVE2-SHA3 RAX1",f_sha3);
  probe("SVE MUL .d (64x64 low)",f_mul64);
  probe("SVE UMULH .d (64x64 high)",f_umulh);
  probe("SVE TBL (byte permute)",f_tbl);
  return 0;
}
