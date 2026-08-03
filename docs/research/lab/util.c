#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/qos.h>
#include <pthread/qos.h>
#include <time.h>
#include <stdlib.h>
static double now(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec+1e-9*ts.tv_nsec;}
static uint64_t chain(uint64_t x,uint64_t n){for(uint64_t i=0;i<n;i++)x=x*6364136223846793005ULL+1442695040888963407ULL;return x;}
static volatile uint64_t sink; static uint64_t N=100000000ULL;
typedef struct{int setq;qos_class_t q;}arg_t;
static void*w(void*a){arg_t*r=a;if(r->setq)pthread_set_qos_class_self_np(r->q,0);sink+=chain(1,N);return 0;}
static double pool(int nt,int setw,qos_class_t wq){
  arg_t a={setw,wq};pthread_t*t=calloc(nt,sizeof(pthread_t));
  double t0=now();for(int i=0;i<nt;i++)pthread_create(&t[i],NULL,w,&a);
  for(int i=0;i<nt;i++)pthread_join(t[i],NULL);double t1=now();free(t);
  return (double)N*nt/(t1-t0)/1e6;}
int main(){
  const int NT=10,R=8;
  double bn=0,bu=0,bb=0;
  for(int i=0;i<R;i++){
    double a=pool(NT,0,0);              if(a>bn)bn=a;
    double b=pool(NT,1,QOS_CLASS_UTILITY);    if(b>bu)bu=b;
    double c=pool(NT,1,QOS_CLASS_BACKGROUND); if(c>bb)bb=c;
    printf("  rep%d  none %7.1f | UTILITY %7.1f (%.3fx) | BACKGROUND %7.1f (%.3fx)\n",i,a,b,b/a,c,c/a);
  }
  printf("\nBEST-of-%d: none %.1f | UTILITY %.1f (%.3fx) | BACKGROUND %.1f (%.3fx)\n",
     R,bn,bu,bu/bn,bb,bb/bn);
  printf("regression factor if forced to BACKGROUND: %.2fx slower\n", bn/bb);
  return 0;}
