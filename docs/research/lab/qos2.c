#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/qos.h>
#include <pthread/qos.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

static double now(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec+1e-9*ts.tv_nsec; }
static uint64_t chain(uint64_t x, uint64_t n){
  for(uint64_t i=0;i<n;i++) x = x*6364136223846793005ULL + 1442695040888963407ULL;
  return x;
}
const char* qname(qos_class_t q){switch(q){
  case QOS_CLASS_USER_INTERACTIVE:return "USER_INTERACTIVE";
  case QOS_CLASS_USER_INITIATED:return "USER_INITIATED";
  case QOS_CLASS_DEFAULT:return "DEFAULT";
  case QOS_CLASS_UTILITY:return "UTILITY";
  case QOS_CLASS_BACKGROUND:return "BACKGROUND";default:return "UNSPEC";}}

static uint64_t NITER = 200000000ULL;
typedef struct { qos_class_t q; int setq; double mops; qos_class_t got; } arg_t;
static volatile uint64_t g_sink;

static void* worker(void* a){
  arg_t* r=(arg_t*)a;
  if(r->setq) pthread_set_qos_class_self_np(r->q,0);
  int rel; pthread_get_qos_class_np(pthread_self(), &r->got, &rel);
  uint64_t s = chain(1, NITER/20);            // warmup
  double t0=now(); s += chain(3,NITER); double t1=now();
  g_sink += s;
  r->mops = NITER/(t1-t0)/1e6;
  return NULL;
}

static double run_pool(qos_class_t q, int nthreads, int setq, qos_class_t* observed){
  arg_t* args=calloc(nthreads,sizeof(arg_t));
  pthread_t* th=calloc(nthreads,sizeof(pthread_t));
  for(int i=0;i<nthreads;i++){args[i].q=q;args[i].setq=setq;}
  double t0=now();
  for(int i=0;i<nthreads;i++) pthread_create(&th[i],NULL,worker,&args[i]);
  for(int i=0;i<nthreads;i++) pthread_join(th[i],NULL);
  double t1=now();
  if(observed) *observed=args[0].got;
  double agg = (double)NITER*nthreads/(t1-t0)/1e6;   // includes warmup, so conservative-uniform
  free(args);free(th);
  return agg;
}

int main(int argc,char**argv){
  qos_class_t classes[]={QOS_CLASS_USER_INTERACTIVE,QOS_CLASS_USER_INITIATED,QOS_CLASS_DEFAULT,QOS_CLASS_UTILITY,QOS_CLASS_BACKGROUND};

  printf("=== A: single thread, 3 interleaved reps (Mmul/s) ===\n");
  double best[5]={0,0,0,0,0};
  for(int rep=0;rep<3;rep++)
    for(int i=0;i<5;i++){
      qos_class_t o; double v=run_pool(classes[i],1,1,&o);
      if(v>best[i]) best[i]=v;
      printf("  rep%d %-18s %7.1f  (observed %s)\n",rep,qname(classes[i]),v,qname(o));
    }
  printf("\n  BEST-of-3 single-thread:\n");
  for(int i=0;i<5;i++) printf("   %-18s %7.1f   ratio_vs_UI %.3fx\n",qname(classes[i]),best[i],best[i]/best[0]);

  printf("\n=== B: 10-thread pool aggregate (Mmul/s total), best of 2 ===\n");
  double bagg[5]={0,0,0,0,0};
  for(int rep=0;rep<2;rep++)
    for(int i=0;i<5;i++){
      double v=run_pool(classes[i],10,1,NULL);
      if(v>bagg[i]) bagg[i]=v;
    }
  for(int i=0;i<5;i++) printf("   %-18s %8.1f   ratio_vs_UI %.3fx\n",qname(classes[i]),bagg[i],bagg[i]/bagg[0]);

  printf("\n=== C: QoS inheritance — parent sets BACKGROUND, children set NOTHING ===\n");
  pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND,0);
  qos_class_t o; double inh1 = run_pool(0,1,0,&o);
  printf("   child observed QoS = %s  -> %.1f Mmul/s (single)\n", qname(o), inh1);
  double inh10 = run_pool(0,10,0,NULL);
  printf("   10-thread aggregate under inherited BACKGROUND: %.1f\n", inh10);
  pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED,0);
  double up10 = run_pool(0,10,0,NULL);
  printf("   10-thread aggregate under inherited USER_INITIATED: %.1f  -> regression %.2fx\n", up10, up10/inh10);
  return 0;
}
