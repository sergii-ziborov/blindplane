#include <stdio.h>
#include <stdint.h>
#include <string.h>
int8_t A[64] __attribute__((aligned(256)));
int8_t B[64] __attribute__((aligned(256)));
int32_t Z[16*16] __attribute__((aligned(256)));
int main(void){ setbuf(stdout,NULL);
  for(int i=0;i<64;i++){A[i]=(int8_t)(i+1); B[i]=(int8_t)((i%3)+1);}
  memset(Z,0,sizeof Z);
  __asm__ volatile("smstart\n zero {za}\n ptrue p0.b\n"
    "ld1b {z0.b}, p0/z, [%0]\n ld1b {z1.b}, p0/z, [%1]\n"
    "smopa za0.s, p0/m, p0/m, z0.b, z1.b\n"
    "mov w12, #0\n mov x9, %2\n"
    "1:\n st1w {za0h.s[w12, 0]}, p0, [x9]\n add x9, x9, #64\n add w12, w12, #1\n cmp w12, #16\n b.lt 1b\n"
    "smstop\n" :: "r"(A),"r"(B),"r"(Z) : "memory","z0","z1","p0","w12","x9");
  int bad=0;
  for(int r=0;r<16;r++) for(int c=0;c<16;c++){
    int32_t ref=0; for(int k=0;k<4;k++) ref += (int32_t)A[r*4+k]*(int32_t)B[c*4+k];
    if(Z[r*16+c]!=ref) bad++;
  }
  printf("SMOPA vs reference Z[r][c]=sum_k A[c*4+k]*B[r*4+k]: %s (%d/256 mismatch)\n", bad?"FAIL":"EXACT", bad);
  printf("sample Z[0][0..3] = %d %d %d %d\n", Z[0],Z[1],Z[2],Z[3]);
  printf("A[0..7]=%d %d %d %d %d %d %d %d  B[0..7]=%d %d %d %d %d %d %d %d\n",
    A[0],A[1],A[2],A[3],A[4],A[5],A[6],A[7],B[0],B[1],B[2],B[3],B[4],B[5],B[6],B[7]);
  return 0; }
