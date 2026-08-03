#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arm_sve.h>
__attribute__((target("sme"))) static uint64_t rdsvl_only(void){
  uint64_t v; __asm__ volatile("rdsvl %0, #1" : "=r"(v)); return v; }
__attribute__((target("sme"))) static void smstart_only(void){
  __asm__ volatile("smstart sm\n\tsmstop sm"); }
__attribute__((target("sme2"))) __arm_locally_streaming static uint64_t cntb_stream(void){ return svcntb(); }
int main(int argc,char**argv){
  int step = atoi(argv[1]);
  if(step==0){ printf("rdsvl = %llu bytes\n",(unsigned long long)rdsvl_only()); }
  if(step==1){ smstart_only(); printf("smstart/smstop OK\n"); }
  if(step==2){ printf("streaming svcntb = %llu\n",(unsigned long long)cntb_stream()); }
  return 0;
}
