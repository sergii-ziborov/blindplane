#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
int main(int argc,char**argv){
  int which = argc>1?atoi(argv[1]):0;
  if(which==0){
    fprintf(stderr,"[test] executing AdvSIMD 'add v0.4s,v0.4s,v1.4s' INSIDE streaming mode\n");fflush(stderr);
    __asm__ volatile("smstart sm\n\t add v0.4s,v0.4s,v1.4s\n\t smstop sm\n\t":::"v0","v1","memory");
    fprintf(stderr,"[test] SURVIVED -> AdvSIMD is LEGAL in streaming mode\n");fflush(stderr);
  } else if(which==1){
    fprintf(stderr,"[test] executing AdvSIMD ld1 {v0.16b},[sp] INSIDE streaming mode\n");fflush(stderr);
    __asm__ volatile("smstart sm\n\t mov x9,sp\n\t ld1 {v0.16b},[x9]\n\t smstop sm\n\t":::"v0","x9","memory");
    fprintf(stderr,"[test] SURVIVED -> AdvSIMD load LEGAL in streaming mode\n");fflush(stderr);
  } else if(which==2){
    fprintf(stderr,"[test] AES instruction 'aese v0.16b,v1.16b' INSIDE streaming mode\n");fflush(stderr);
    __asm__ volatile("smstart sm\n\t aese v0.16b,v1.16b\n\t smstop sm\n\t":::"v0","v1","memory");
    fprintf(stderr,"[test] SURVIVED -> AES LEGAL in streaming mode\n");fflush(stderr);
  } else if(which==3){
    fprintf(stderr,"[test] scalar FP 'fadd d0,d0,d1' INSIDE streaming mode\n");fflush(stderr);
    __asm__ volatile("smstart sm\n\t fadd d0,d0,d1\n\t smstop sm\n\t":::"d0","d1","memory");
    fprintf(stderr,"[test] SURVIVED -> scalar FP LEGAL in streaming mode\n");fflush(stderr);
  } else if(which==4){
    fprintf(stderr,"[test] scalar integer 'madd x0,x1,x2,x3' INSIDE streaming mode\n");fflush(stderr);
    __asm__ volatile("smstart sm\n\t madd x0,x1,x2,x3\n\t smstop sm\n\t":::"x0","memory");
    fprintf(stderr,"[test] SURVIVED -> scalar int LEGAL in streaming mode\n");fflush(stderr);
  }
  return 0;
}
