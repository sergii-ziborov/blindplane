#include <stdio.h>
#include <stdint.h>
#include <time.h>
static inline uint64_t ns(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1000000000ull+t.tv_nsec; }
#define N 2000000
int main(void){ setbuf(stdout,NULL);
  volatile uint64_t sink=0; uint64_t t0,t1;
  // baseline empty loop
  t0=ns(); for(int i=0;i<N;i++) __asm__ volatile("":::"memory"); t1=ns();
  double base=(double)(t1-t0)/N; printf("empty loop            : %.2f ns/iter\n", base);
  // smstart sm / smstop sm pair
  t0=ns(); for(int i=0;i<N;i++) __asm__ volatile("smstart sm\n smstop sm":::"memory"); t1=ns();
  printf("smstart sm+smstop sm  : %.2f ns/iter (%.2f ns net)\n",(double)(t1-t0)/N,(double)(t1-t0)/N-base);
  // full smstart/smstop (SM+ZA)
  t0=ns(); for(int i=0;i<N;i++) __asm__ volatile("smstart\n smstop":::"memory"); t1=ns();
  printf("smstart+smstop (SM+ZA): %.2f ns/iter (%.2f ns net)\n",(double)(t1-t0)/N,(double)(t1-t0)/N-base);
  // zero {za} cost inside streaming
  t0=ns(); for(int i=0;i<N;i++) __asm__ volatile("smstart\n zero {za}\n smstop":::"memory"); t1=ns();
  printf("smstart+zero za+smstop: %.2f ns/iter\n",(double)(t1-t0)/N);
  return 0; }
