#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
static sigjmp_buf jb; static volatile const char* what;
static void h(int s,siginfo_t*si,void*uc){ucontext_t*u=(ucontext_t*)uc;
  fprintf(stderr,"  SIGILL insn=0x%08x during %s\n",*(uint32_t*)u->uc_mcontext->__ss.__pc,what);siglongjmp(jb,1);}
#define TRY(n,c) do{what=n; if(sigsetjmp(jb,1)==0){c; printf("  OK: %s\n",n);} }while(0)

int8_t A[64] __attribute__((aligned(256)));
int8_t B[64] __attribute__((aligned(256)));
int32_t Z[16*16] __attribute__((aligned(256)));

int main(void){ setbuf(stdout,NULL);
  struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_sigaction=h; sa.sa_flags=SA_SIGINFO; sigaction(SIGILL,&sa,NULL);
  for(int i=0;i<64;i++){A[i]=(int8_t)(i+1); B[i]=(int8_t)((i%3)+1);}
  memset(Z,0,sizeof Z);

  // SMOPA: i8 x i8 -> i32 outer product accumulate into ZA tile.
  // SVL=512b -> 64 bytes/vector, i32 tile is 16x16, each element = 4-way dot product.
  TRY("smopa za0.s (i8->i32 outer product)", {
    __asm__ volatile(
      "smstart\n"
      "zero {za}\n"
      "ptrue p0.b\n"
      "ld1b {z0.b}, p0/z, [%0]\n"
      "ld1b {z1.b}, p0/z, [%1]\n"
      "smopa za0.s, p0/m, p0/m, z0.b, z1.b\n"
      "mov w12, #0\n"
      "mov x9, %2\n"
      "1:\n"
      "st1w {za0h.s[w12, 0]}, p0, [x9]\n"
      "add x9, x9, #64\n"
      "add w12, w12, #1\n"
      "cmp w12, #16\n"
      "b.lt 1b\n"
      "smstop\n"
      :: "r"(A), "r"(B), "r"(Z)
      : "memory","z0","z1","p0","w12","x9");
  });

  // Verify against scalar reference: Z[j][i] = sum_k A[i*4+k]*B[j*4+k]
  int bad=0;
  for(int j=0;j<16;j++) for(int i=0;i<16;i++){
    int32_t r=0; for(int k=0;k<4;k++) r += (int32_t)A[i*4+k]*(int32_t)B[j*4+k];
    if(Z[j*16+i]!=r){ if(bad<3) printf("  MISMATCH z[%d][%d] got %d want %d\n",j,i,Z[j*16+i],r); bad++; }
  }
  printf("  SMOPA correctness vs scalar reference: %s (%d mismatches of 256)\n", bad?"FAIL":"EXACT MATCH", bad);

  // Is NEON usable INSIDE streaming mode?
  TRY("NEON add v0.16b inside streaming", __asm__ volatile("smstart sm\n add v0.16b, v0.16b, v0.16b\n smstop sm":::"v0"));
  TRY("AES aese v0 inside streaming",     __asm__ volatile("smstart sm\n aese v0.16b, v1.16b\n smstop sm":::"v0"));
  TRY("PMULL inside streaming",           __asm__ volatile("smstart sm\n pmull v0.1q, v1.1d, v2.1d\n smstop sm":::"v0"));
  TRY("SHA256H inside streaming",         __asm__ volatile("smstart sm\n sha256h q0, q1, v2.4s\n smstop sm":::"v0","v1","v2"));
  return 0; }
