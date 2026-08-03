// Measure the ACTUAL memory patterns, not just memcpy.
//   copy : read src + write dst   (2 streams, 2x footprint per byte "processed")
//   rmw  : in-place read-modify-write  <-- this is exactly what in-place AEAD does
//   read : pure read stream
// Working set is per-thread and fixed in MiB so total footprint is predictable.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <arm_neon.h>
static size_t PER;           // bytes per thread per buffer
static int NT; static int MODE; static double SECS;
static volatile int stop=0;
static _Atomic unsigned long long tot=0;
static _Atomic unsigned long long sinkv=0;

static void* w(void*arg){
  (void)arg;
  char *s=aligned_alloc(16384,PER), *d=NULL;
  if(MODE==0) d=aligned_alloc(16384,PER);
  memset(s,1,PER); if(d) memset(d,2,PER);
  unsigned long long l=0; uint64x2_t acc=vdupq_n_u64(0);
  while(!stop){
    if(MODE==0){ memcpy(d,s,PER); asm volatile("":::"memory"); }
    else if(MODE==1){ // in-place RMW: xor a constant into every 16B lane, in place
      uint8x16_t k=vdupq_n_u8(0x5a);
      for(size_t i=0;i<PER;i+=64){
        uint8x16_t a=vld1q_u8((uint8_t*)s+i),   b=vld1q_u8((uint8_t*)s+i+16);
        uint8x16_t c=vld1q_u8((uint8_t*)s+i+32),e=vld1q_u8((uint8_t*)s+i+48);
        vst1q_u8((uint8_t*)s+i,    veorq_u8(a,k)); vst1q_u8((uint8_t*)s+i+16, veorq_u8(b,k));
        vst1q_u8((uint8_t*)s+i+32, veorq_u8(c,k)); vst1q_u8((uint8_t*)s+i+48, veorq_u8(e,k));
      }
      asm volatile("":::"memory");
    } else { // pure read
      uint64x2_t a0=vdupq_n_u64(0);
      for(size_t i=0;i<PER;i+=64){
        a0=veorq_u64(a0,vld1q_u64((uint64_t*)((char*)s+i)));
        a0=veorq_u64(a0,vld1q_u64((uint64_t*)((char*)s+i+16)));
        a0=veorq_u64(a0,vld1q_u64((uint64_t*)((char*)s+i+32)));
        a0=veorq_u64(a0,vld1q_u64((uint64_t*)((char*)s+i+48)));
      }
      acc=veorq_u64(acc,a0);
      asm volatile("":::"memory");
    }
    l+=PER;
  }
  sinkv+=vgetq_lane_u64(acc,0)+(unsigned long long)s[0];
  tot+=l; return 0;
}
int main(int c,char**v){
  if(c<4){fprintf(stderr,"usage: rl2 <threads> <MiB per thread> <copy|rmw|read> [secs]\n");return 1;}
  NT=atoi(v[1]); PER=(size_t)atoi(v[2])<<20;
  MODE = strcmp(v[3],"copy")==0?0: strcmp(v[3],"rmw")==0?1:2;
  SECS = c>4?atof(v[4]):2.0;
  pthread_t t[64];
  for(int i=0;i<NT;i++)pthread_create(&t[i],0,w,0);
  struct timespec a,b; clock_gettime(CLOCK_MONOTONIC,&a);
  struct timespec ts={(long)SECS,(long)((SECS-(long)SECS)*1e9)}; nanosleep(&ts,0);
  stop=1;
  for(int i=0;i<NT;i++)pthread_join(t[i],0);
  clock_gettime(CLOCK_MONOTONIC,&b);
  double dt=(b.tv_sec-a.tv_sec)+(b.tv_nsec-a.tv_nsec)*1e-9;
  double g=(double)tot/dt/1e9;
  double traffic = MODE==2 ? g : 2*g;
  double foot = (double)PER*NT*(MODE==0?2:1)/1048576.0;
  printf("%-5s %2d thr  %6.0f MiB footprint : %6.1f GB/s processed = %6.1f GB/s DRAM traffic\n",
         v[3],NT,foot,g,traffic);
  return 0;}
