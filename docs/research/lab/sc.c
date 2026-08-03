#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (uint64_t)ts.tv_sec*1000000000ull+ts.tv_nsec;}
static void*w(void*p){volatile uint64_t a=1,b=3,s=0;for(int64_t i=0;i<200000000;i++){s+=a*b;}*(uint64_t*)p=s;return 0;}
int main(){pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0);
 for(int nt=1;nt<=8;nt*=2){pthread_t t[8];uint64_t r[8];uint64_t t0=nowi();
  for(int i=0;i<nt;i++)pthread_create(&t[i],0,w,&r[i]);
  for(int i=0;i<nt;i++)pthread_join(t[i],0);uint64_t t1=nowi();
  printf("scalar MUL %d thread(s): aggregate %.2f G mul/s\n",nt,(double)nt*200000000/(double)(t1-t0));}
 return 0;}
