#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <mach/thread_act.h>
#include <sys/qos.h>
#include <pthread/qos.h>
#include <time.h>
#include <string.h>

static double now(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec+1e-9*ts.tv_nsec; }

// dependent 64-bit multiply chain: pure latency-bound, ~1 mul/cycle dependency
static uint64_t chain(uint64_t x, uint64_t n){
  for(uint64_t i=0;i<n;i++){ x = x*6364136223846793005ULL + 1442695040888963407ULL; }
  return x;
}

const char* qname(qos_class_t q){
  switch(q){case QOS_CLASS_USER_INTERACTIVE:return "USER_INTERACTIVE";
  case QOS_CLASS_USER_INITIATED:return "USER_INITIATED";
  case QOS_CLASS_DEFAULT:return "DEFAULT";
  case QOS_CLASS_UTILITY:return "UTILITY";
  case QOS_CLASS_BACKGROUND:return "BACKGROUND";
  default:return "UNSPEC";}
}

typedef struct { qos_class_t q; double mops; int setrc; qos_class_t got; } res_t;

static void* worker(void* arg){
  res_t* r = (res_t*)arg;
  r->setrc = pthread_set_qos_class_self_np(r->q, 0);
  qos_class_t g; int rel; pthread_get_qos_class_np(pthread_self(), &g, &rel);
  r->got = g;
  volatile uint64_t sink=0;
  // warmup
  sink += chain(1, 50000000ULL);
  uint64_t N = 300000000ULL;
  double t0=now(); sink += chain(3,N); double t1=now();
  r->mops = N/(t1-t0)/1e6;
  (void)sink;
  return NULL;
}

int main(void){
  // --- Test A: THREAD_AFFINITY_POLICY return code on arm64 ---
  thread_affinity_policy_data_t pol = { 1 };
  kern_return_t kr = thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY,
      (thread_policy_t)&pol, THREAD_AFFINITY_POLICY_COUNT);
  printf("thread_policy_set(THREAD_AFFINITY_POLICY) -> %d (%s)\n", kr,
      kr==KERN_SUCCESS?"KERN_SUCCESS":(kr==KERN_NOT_SUPPORTED?"KERN_NOT_SUPPORTED":"other"));

  // readback
  thread_affinity_policy_data_t got; mach_msg_type_number_t cnt=THREAD_AFFINITY_POLICY_COUNT;
  boolean_t def=FALSE;
  kern_return_t kr2 = thread_policy_get(mach_thread_self(), THREAD_AFFINITY_POLICY,
      (thread_policy_t)&got, &cnt, &def);
  printf("thread_policy_get -> %d, affinity_tag=%d, get_default=%d\n", kr2, got.affinity_tag, def);

  // --- Test B: throughput per QoS class ---
  qos_class_t classes[] = {QOS_CLASS_USER_INTERACTIVE, QOS_CLASS_USER_INITIATED,
                           QOS_CLASS_DEFAULT, QOS_CLASS_UTILITY, QOS_CLASS_BACKGROUND};
  printf("\n%-18s %-8s %-18s %s\n","requested","setrc","observed","Mmul/s (dependent)");
  for(int i=0;i<5;i++){
    res_t r; memset(&r,0,sizeof r); r.q=classes[i];
    pthread_t t; pthread_create(&t,NULL,worker,&r); pthread_join(t,NULL);
    printf("%-18s %-8d %-18s %.1f\n", qname(classes[i]), r.setrc, qname(r.got), r.mops);
  }
  return 0;
}
