#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char**argv){ setbuf(stdout,NULL); int t=atoi(argv[1]);
  switch(t){
   case 0: __asm__ volatile("smstart sm\n add v0.16b, v0.16b, v0.16b\n smstop sm":::"v0"); puts("OK neon-add"); break;
   case 1: __asm__ volatile("smstart sm\n aese v0.16b, v1.16b\n smstop sm":::"v0","v1"); puts("OK aese"); break;
   case 2: __asm__ volatile("smstart sm\n pmull v0.1q, v1.1d, v2.1d\n smstop sm":::"v0","v1","v2"); puts("OK pmull"); break;
   case 3: __asm__ volatile("smstart sm\n sha256h q0, q1, v2.4s\n smstop sm":::"v0","v1","v2"); puts("OK sha256h"); break;
   case 4: __asm__ volatile("smstart sm\n tbl v0.16b, {v1.16b}, v2.16b\n smstop sm":::"v0","v1","v2"); puts("OK tbl"); break;
   case 5: __asm__ volatile("smstart sm\n rev64 v0.4s, v1.4s\n smstop sm":::"v0","v1"); puts("OK rev64"); break;
  }
  return 0; }
