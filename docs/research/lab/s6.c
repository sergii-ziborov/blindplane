#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
static int probe(const char*name, void(*fn)(void)){
  fflush(stdout);
  pid_t p=fork();
  if(p==0){ fn(); _exit(0); }
  int st; waitpid(p,&st,0);
  int ok = WIFEXITED(st)&&WEXITSTATUS(st)==0;
  printf("%-30s %s\n", name, ok?"OK":(WIFSIGNALED(st)?(WTERMSIG(st)==4?"SIGILL":"signal"):"fail"));
  return ok;
}
static void f_rdsvl(void){ uint64_t n; __asm__ volatile("rdsvl %0, #1":"=r"(n)); if(n!=64)_exit(9); }
static void f_smstart_sm(void){ __asm__ volatile("smstart sm"); __asm__ volatile("smstop sm"); }
static void f_smstart_za(void){ __asm__ volatile("smstart za"); __asm__ volatile("smstop za"); }
static void f_zeroza(void){ __asm__ volatile("smstart"); __asm__ volatile("zero {za}"); __asm__ volatile("smstop"); }
static void f_smopa8(void){
  int8_t a[64],b[64]; int32_t o[16];
  for(int i=0;i<64;i++){a[i]=i+1;b[i]=2*i+1;}
  __asm__ volatile("smstart\n\t"
    "ptrue p0.b\n\t" "ld1b {z0.b}, p0/z, [%0]\n\t" "ld1b {z1.b}, p0/z, [%1]\n\t"
    "zero {za}\n\t" "smopa za0.s, p0/m, p0/m, z0.b, z1.b\n\t"
    "ptrue p1.s\n\t" "mov w12, wzr\n\t" "mova z2.s, p1/m, za0h.s[w12,0]\n\t"
    "st1w {z2.s}, p1, [%2]\n\t" "smstop\n\t"
    :: "r"(a),"r"(b),"r"(o):"z0","z1","z2","p0","p1","x12","memory");
  fprintf(stderr,"  i8 smopa row0: %d %d %d %d\n",o[0],o[1],o[2],o[3]);
}
static void f_smopa16(void){
  int16_t a[32],b[32]; int64_t o[8];
  for(int i=0;i<32;i++){a[i]=i+1;b[i]=2*i+1;}
  __asm__ volatile("smstart\n\t"
    "ptrue p0.h\n\t" "ld1h {z0.h}, p0/z, [%0]\n\t" "ld1h {z1.h}, p0/z, [%1]\n\t"
    "zero {za}\n\t" "smopa za0.d, p0/m, p0/m, z0.h, z1.h\n\t"
    "ptrue p1.d\n\t" "mov w12, wzr\n\t" "mova z2.d, p1/m, za0h.d[w12,0]\n\t"
    "st1d {z2.d}, p1, [%2]\n\t" "smstop\n\t"
    :: "r"(a),"r"(b),"r"(o):"z0","z1","z2","p0","p1","x12","memory");
  fprintf(stderr,"  i16 smopa row0: %lld %lld %lld %lld\n",(long long)o[0],(long long)o[1],(long long)o[2],(long long)o[3]);
}
static void f_eor(void){ __asm__ volatile("smstart\n\t eor z0.d,z0.d,z1.d\n\t smstop":::"z0"); }
static void f_nonstream_sve(void){ __asm__ volatile("ptrue p0.b" ::: "p0"); } // SVE outside streaming
int main(void){
  probe("rdsvl (non-streaming)",f_rdsvl);
  probe("smstart/smstop sm",f_smstart_sm);
  probe("smstart/smstop za",f_smstart_za);
  probe("zero {za}",f_zeroza);
  probe("SMOPA i8->i32",f_smopa8);
  probe("SMOPA i16->i64",f_smopa16);
  probe("EOR z (bitwise, streaming)",f_eor);
  probe("SVE ptrue OUTSIDE streaming",f_nonstream_sve);
  return 0;
}
