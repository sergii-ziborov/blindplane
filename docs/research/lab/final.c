#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/qos.h>
#include <pthread/qos.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
static double now(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec+1e-9*ts.tv_nsec;}
static uint64_t chain(uint64_t x,uint64_t n){for(uint64_t i=0;i<n;i++)x=x*6364136223846793005ULL+1442695040888963407ULL;return x;}
static volatile uint64_t sink;
static uint64_t N=120000000ULL;
typedef struct{int setq;qos_class_t q;}arg_t;
static void* w(void*a){arg_t*r=a;if(r->setq)pthread_set_qos_class_self_np(r->q,0);sink+=chain(1,N);return 0;}
// returns aggregate Mmul/s for `nt` threads; parent QoS = pq (if setp), workers set own QoS if setw
static double pool(int nt,int setp,qos_class_t pq,int setw,qos_class_t wq){
  if(setp) pthread_set_qos_class_self_np(pq,0);
  arg_t a={setw,wq};
  pthread_t*t=calloc(nt,sizeof(pthread_t));
  double t0=now();
  for(int i=0;i<nt;i++)pthread_create(&t[i],NULL,w,&a);
  for(int i=0;i<nt;i++)pthread_join(t[i],NULL);
  double t1=now();free(t);
  return (double)N*nt/(t1-t0)/1e6;
}
int main(){
  const int NT=10, REPS=5;
  struct { const char*name; int setp; qos_class_t pq; int setw; qos_class_t wq; double best; }
  cases[] = {
   {"parent=UI_INITIATED, workers=inherit(none)", 1,QOS_CLASS_USER_INITIATED,0,0,0},
   {"parent=BACKGROUND,   workers=inherit(none)", 1,QOS_CLASS_BACKGROUND,    0,0,0},
   {"parent=UTILITY,      workers=inherit(none)", 1,QOS_CLASS_UTILITY,       0,0,0},
   {"parent=any, workers EXPLICIT BACKGROUND   ", 1,QOS_CLASS_USER_INITIATED,1,QOS_CLASS_BACKGROUND,0},
   {"parent=any, workers EXPLICIT UTILITY      ", 1,QOS_CLASS_USER_INITIATED,1,QOS_CLASS_UTILITY,0},
   {"parent=any, workers EXPLICIT USER_INITIATED",1,QOS_CLASS_USER_INITIATED,1,QOS_CLASS_USER_INITIATED,0},
  };
  int n=sizeof(cases)/sizeof(cases[0]);
  for(int r=0;r<REPS;r++)
    for(int i=0;i<n;i++){
      double v=pool(NT,cases[i].setp,cases[i].pq,cases[i].setw,cases[i].wq);
      if(v>cases[i].best)cases[i].best=v;
    }
  printf("10-thread aggregate, BEST of %d interleaved reps (Mmul/s):\n\n",REPS);
  double ref=cases[0].best;
  for(int i=0;i<n;i++)
    printf("  %-44s %8.1f   %.3fx\n",cases[i].name,cases[i].best,cases[i].best/ref);
  return 0;
}
