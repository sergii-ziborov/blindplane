#include <stdio.h>
#include <stdlib.h>
int main(int argc,char**argv){ setbuf(stdout,NULL);
  switch(atoi(argv[1])){
   case 0: __asm__ volatile("smstart sm\n add z0.b, z0.b, z0.b\n smstop sm":::"z0"); puts("OK SVE add z0.b (streaming)"); break;
   case 1: __asm__ volatile("smstart sm\n eor z0.d, z0.d, z1.d\n smstop sm":::"z0","z1"); puts("OK SVE eor z.d"); break;
   case 2: __asm__ volatile("smstart sm\n lsl z0.s, z0.s, #7\n smstop sm":::"z0"); puts("OK SVE lsl (rotate-ish for chacha)"); break;
   case 3: __asm__ volatile("smstart sm\n pmullb z0.q, z1.d, z2.d\n smstop sm":::"z0","z1","z2"); puts("OK SVE PMULLB (would be GHASH)"); break;
   case 4: __asm__ volatile("smstart sm\n aese z0.b, z0.b, z1.b\n smstop sm":::"z0","z1"); puts("OK SVE AESE (would be AES)"); break;
   case 5: __asm__ volatile("smstart sm\n tbl z0.b, {z1.b}, z2.b\n smstop sm":::"z0","z1","z2"); puts("OK SVE TBL"); break;
  }
  return 0; }
