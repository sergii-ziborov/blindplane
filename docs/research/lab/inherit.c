#include <stdio.h>
#include <pthread.h>
#include <sys/qos.h>
#include <pthread/qos.h>
#include <dispatch/dispatch.h>
const char* qn(qos_class_t q){switch(q){
 case QOS_CLASS_USER_INTERACTIVE:return "USER_INTERACTIVE";
 case QOS_CLASS_USER_INITIATED:return "USER_INITIATED";
 case QOS_CLASS_DEFAULT:return "DEFAULT";
 case QOS_CLASS_UTILITY:return "UTILITY";
 case QOS_CLASS_BACKGROUND:return "BACKGROUND";
 case QOS_CLASS_UNSPECIFIED:return "UNSPECIFIED";default:return "?";}}
static void* child(void*_){
  qos_class_t q;int r;pthread_get_qos_class_np(pthread_self(),&q,&r);
  printf("      pthread_create child QoS = %-18s (rel %d)\n",qn(q),r);
  // grandchild
  return 0;
}
static void probe(const char* label){
  qos_class_t q;int r;pthread_get_qos_class_np(pthread_self(),&q,&r);
  printf("   [%s] self QoS = %s\n",label,qn(q));
  pthread_t t;pthread_create(&t,NULL,child,NULL);pthread_join(t,NULL);
}
int main(){
  printf("== pthread_create inheritance ==\n");
  qos_class_t cs[]={QOS_CLASS_USER_INTERACTIVE,QOS_CLASS_USER_INITIATED,QOS_CLASS_UTILITY,QOS_CLASS_BACKGROUND};
  for(int i=0;i<4;i++){
    pthread_set_qos_class_self_np(cs[i],0);
    probe(qn(cs[i]));
  }
  printf("\n== inside dispatch_async on global BACKGROUND queue (the actual claimed footgun) ==\n");
  dispatch_semaphore_t s=dispatch_semaphore_create(0);
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND,0),^{
     probe("GCD .background block");
     dispatch_semaphore_signal(s);
  });
  dispatch_semaphore_wait(s,DISPATCH_TIME_FOREVER);
  printf("\n== inside dispatch_async on global UTILITY queue ==\n");
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
     probe("GCD .utility block");
     dispatch_semaphore_signal(s);
  });
  dispatch_semaphore_wait(s,DISPATCH_TIME_FOREVER);
  return 0;
}
