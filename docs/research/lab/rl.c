#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
static unsigned long long N;
int NT; volatile int stop=0; _Atomic unsigned long long tot=0; _Atomic unsigned sink=0;
void* w(void*a){ size_t n=N/NT; char*s=malloc(n),*d=malloc(n); memset(s,1,n); memset(d,2,n);
  unsigned long long l=0; unsigned acc=0;
  while(!stop){ memcpy(d,s,n); acc+=d[l%n]; asm volatile("":::"memory"); l+=n; }
  sink+=acc; tot+=l; return 0;}
int main(int c,char**v){ NT=atoi(v[1]); N=(unsigned long long)atoi(v[2])<<20;
  pthread_t t[64];
  struct timespec a,b; clock_gettime(CLOCK_MONOTONIC,&a);
  for(int i=0;i<NT;i++)pthread_create(&t[i],0,w,0);
  struct timespec ts={2,0}; nanosleep(&ts,0); stop=1;
  for(int i=0;i<NT;i++)pthread_join(t[i],0);
  clock_gettime(CLOCK_MONOTONIC,&b);
  double dt=(b.tv_sec-a.tv_sec)+(b.tv_nsec-a.tv_nsec)*1e-9;
  double g=(double)tot/dt/1e9;
  printf("%2d threads, %4llu MiB total: %6.1f GB/s copied = %6.1f GB/s DRAM traffic\n",NT,N>>20,g,2*g);
  return 0;}
