#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}
#define CL "memory","cc","v8","v9","v10","v11","v12","v13","v14","v15"
static void k_smopa(int64_t it,const int16_t*a,const int16_t*b){
 __asm__ volatile("smstart\n\t ptrue p0.h\n\t ld1h {z0.h},p0/z,[%1]\n\t ld1h {z1.h},p0/z,[%2]\n\t zero {za}\n\t"
  "1:\n\t smopa za0.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za1.d,p0/m,p0/m,z0.h,z1.h\n\t"
  "smopa za2.d,p0/m,p0/m,z0.h,z1.h\n\t smopa za3.d,p0/m,p0/m,z0.h,z1.h\n\t"
  "subs %0,%0,#1\n\t bne 1b\n\t smstop\n\t":"+r"(it):"r"(a),"r"(b):"z0","z1","p0",CL);}
static void k_xar(int64_t it,const uint32_t*s){
 __asm__ volatile("smstart sm\n\t ptrue p0.s\n\t ld1w {z0.s},p0/z,[%1]\n\t mov z1.d,z0.d\n\t mov z2.d,z0.d\n\t mov z3.d,z0.d\n\t"
  "1:\n\t add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#16\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#20\n\t"
  "subs %0,%0,#1\n\t bne 1b\n\t smstop sm\n\t":"+r"(it):"r"(s):"z0","z1","z2","z3","p0",CL);}
static int dit_ok(void){
  pid_t p=fork(); if(!p){ __asm__ volatile("msr DIT, #1"); _exit(0);} int st; waitpid(p,&st,0);
  return WIFEXITED(st)&&!WEXITSTATUS(st);}
static int dit_stream(void){
  pid_t p=fork(); if(!p){ __asm__ volatile("smstart sm\n\t msr DIT,#1\n\t smstop sm":::CL); _exit(0);} int st; waitpid(p,&st,0);
  return WIFEXITED(st)&&!WEXITSTATUS(st);}
int main(void){
  int16_t z[32],o[32],r[32],hi[32];
  memset(z,0,sizeof z);
  for(int i=0;i<32;i++){o[i]=1; r[i]=(int16_t)(0x5a5a^(i*2654435761u)); hi[i]=(int16_t)0x7fff;}
  uint32_t sz[16]={0},sr[16]; for(int i=0;i<16;i++) sr[i]=0xdeadbeefu*(i+1);
  int64_t it=3000000;
  const char*nm[4]={"all zeros","all ones","random","all 0x7fff"};
  const int16_t*ps[4]={z,o,r,hi};
  printf("SMOPA i16->i64 timing vs operand content (4 SMOPA/iter, %lld iters):\n",(long long)it);
  for(int i=0;i<4;i++){
    k_smopa(1000,ps[i],ps[i]);
    uint64_t t0=nowi(); k_smopa(it,ps[i],ps[i]); uint64_t t1=nowi();
    printf("  %-12s %.4f ns/SMOPA\n",nm[i],(double)(t1-t0)/(it*4.0));
  }
  printf("XAR/ADD streaming timing vs operand content:\n");
  const char*n2[2]={"all zeros","random"}; const uint32_t*p2[2]={sz,sr};
  for(int i=0;i<2;i++){
    k_xar(1000,p2[i]);
    uint64_t t0=nowi(); k_xar(it,p2[i]); uint64_t t1=nowi();
    printf("  %-12s %.4f ns/iter\n",n2[i],(double)(t1-t0)/it);
  }
  printf("MSR DIT outside streaming: %s\n", dit_ok()?"OK":"SIGILL");
  printf("MSR DIT inside  streaming: %s\n", dit_stream()?"OK":"SIGILL");
  return 0;
}
