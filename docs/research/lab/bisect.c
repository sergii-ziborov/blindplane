#include <stdio.h>
#include <stdlib.h>
int main(int argc,char**argv){
  int w=atoi(argv[1]);
  uint32_t *a=aligned_alloc(64,1<<20),*b=aligned_alloc(64,1<<20);
  fprintf(stderr,"case %d start\n",w); fflush(stderr);
  if(w==0) __asm__ volatile("smstart sm\n\t ptrue p0.s\n\t smstop sm\n\t":::"p0","memory");
  if(w==1) __asm__ volatile("smstart sm\n\t ptrue p0.s\n\t ld1w {z16.s},p0/z,[%0]\n\t smstop sm\n\t"::"r"(a):"p0","z16","memory");
  if(w==2) __asm__ volatile("smstart sm\n\t ptrue p0.s\n\t ld1w {z16.s},p0/z,[%0]\n\t st1w {z16.s},p0,[%1]\n\t smstop sm\n\t"::"r"(a),"r"(b):"p0","z16","memory");
  if(w==3) __asm__ volatile("smstart sm\n\t ptrue p0.s\n\t ld1w {z16.s},p0/z,[%0,#7,mul vl]\n\t smstop sm\n\t"::"r"(a):"p0","z16","memory");
  if(w==4) __asm__ volatile("smstart za\n\t smstop za\n\t":::"memory");
  if(w==5) __asm__ volatile("smstart sm\n\tsmstart za\n\t ptrue p0.s\n\t mov w12,#0\n\t mova za0h.s[w12,0],p0/m,z0.s\n\t smstop za\n\tsmstop sm\n\t":::"p0","w12","za","memory");
  if(w==6) __asm__ volatile("smstart sm\n\tsmstart za\n\t ptrue p0.s\n\t mov w12,#0\n\t mova z0.s,p0/m,za0v.s[w12,0]\n\t smstop za\n\tsmstop sm\n\t":::"p0","w12","za","z0","memory");
  if(w==7) __asm__ volatile("smstart sm\n\t eor z16.d,z16.d,z1.d\n\t smstop sm\n\t":::"z16","z1","memory");
  fprintf(stderr,"case %d SURVIVED\n",w); fflush(stderr);
  return 0;
}
