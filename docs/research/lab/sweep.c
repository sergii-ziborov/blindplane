#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
static uint64_t nowi(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec;}
static void NEONF(int64_t it){
 __asm__ volatile("1:\n\t"
  "add v0.4s,v0.4s,v1.4s\n\t eor v3.16b,v3.16b,v0.16b\n\t rev32 v3.8h,v3.8h\n\t"
  "add v2.4s,v2.4s,v3.4s\n\t eor v24.16b,v1.16b,v2.16b\n\t shl v1.4s,v24.4s,#12\n\t usra v1.4s,v24.4s,#20\n\t"
  "add v0.4s,v0.4s,v1.4s\n\t eor v24.16b,v3.16b,v0.16b\n\t shl v3.4s,v24.4s,#8\n\t usra v3.4s,v24.4s,#24\n\t"
  "add v2.4s,v2.4s,v3.4s\n\t eor v24.16b,v1.16b,v2.16b\n\t shl v1.4s,v24.4s,#7\n\t usra v1.4s,v24.4s,#25\n\t"
  "add v4.4s,v4.4s,v5.4s\n\t eor v7.16b,v7.16b,v4.16b\n\t rev32 v7.8h,v7.8h\n\t"
  "add v6.4s,v6.4s,v7.4s\n\t eor v25.16b,v5.16b,v6.16b\n\t shl v5.4s,v25.4s,#12\n\t usra v5.4s,v25.4s,#20\n\t"
  "add v4.4s,v4.4s,v5.4s\n\t eor v25.16b,v7.16b,v4.16b\n\t shl v7.4s,v25.4s,#8\n\t usra v7.4s,v25.4s,#24\n\t"
  "add v6.4s,v6.4s,v7.4s\n\t eor v25.16b,v5.16b,v6.16b\n\t shl v5.4s,v25.4s,#7\n\t usra v5.4s,v25.4s,#25\n\t"
  "add v8.4s,v8.4s,v9.4s\n\t eor v11.16b,v11.16b,v8.16b\n\t rev32 v11.8h,v11.8h\n\t"
  "add v10.4s,v10.4s,v11.4s\n\t eor v26.16b,v9.16b,v10.16b\n\t shl v9.4s,v26.4s,#12\n\t usra v9.4s,v26.4s,#20\n\t"
  "add v8.4s,v8.4s,v9.4s\n\t eor v26.16b,v11.16b,v8.16b\n\t shl v11.4s,v26.4s,#8\n\t usra v11.4s,v26.4s,#24\n\t"
  "add v10.4s,v10.4s,v11.4s\n\t eor v26.16b,v9.16b,v10.16b\n\t shl v9.4s,v26.4s,#7\n\t usra v9.4s,v26.4s,#25\n\t"
  "add v12.4s,v12.4s,v13.4s\n\t eor v15.16b,v15.16b,v12.16b\n\t rev32 v15.8h,v15.8h\n\t"
  "add v14.4s,v14.4s,v15.4s\n\t eor v27.16b,v13.16b,v14.16b\n\t shl v13.4s,v27.4s,#12\n\t usra v13.4s,v27.4s,#20\n\t"
  "add v12.4s,v12.4s,v13.4s\n\t eor v27.16b,v15.16b,v12.16b\n\t shl v15.4s,v27.4s,#8\n\t usra v15.4s,v27.4s,#24\n\t"
  "add v14.4s,v14.4s,v15.4s\n\t eor v27.16b,v13.16b,v14.16b\n\t shl v13.4s,v27.4s,#7\n\t usra v13.4s,v27.4s,#25\n\t"
  "subs %0,%0,#1\n\t bne 1b\n\t":"+r"(it)::
  "v0","v1","v2","v3","v4","v5","v6","v7","v8","v9","v10","v11","v12","v13","v14","v15","v24","v25","v26","v27","memory","cc");}
static void SVEF(int64_t it){
 __asm__ volatile("smstart sm\n\t1:\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#16\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#20\n\t"
  "add z0.s,z0.s,z1.s\n\t xar z3.s,z3.s,z0.s,#24\n\t add z2.s,z2.s,z3.s\n\t xar z1.s,z1.s,z2.s,#25\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#16\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#20\n\t"
  "add z4.s,z4.s,z5.s\n\t xar z7.s,z7.s,z4.s,#24\n\t add z6.s,z6.s,z7.s\n\t xar z5.s,z5.s,z6.s,#25\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#16\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#20\n\t"
  "add z8.s,z8.s,z9.s\n\t xar z11.s,z11.s,z8.s,#24\n\t add z10.s,z10.s,z11.s\n\t xar z9.s,z9.s,z10.s,#25\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#16\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#20\n\t"
  "add z12.s,z12.s,z13.s\n\t xar z15.s,z15.s,z12.s,#24\n\t add z14.s,z14.s,z15.s\n\t xar z13.s,z13.s,z14.s,#25\n\t"
  "add z16.s,z16.s,z17.s\n\t xar z19.s,z19.s,z16.s,#16\n\t add z18.s,z18.s,z19.s\n\t xar z17.s,z17.s,z18.s,#20\n\t"
  "add z16.s,z16.s,z17.s\n\t xar z19.s,z19.s,z16.s,#24\n\t add z18.s,z18.s,z19.s\n\t xar z17.s,z17.s,z18.s,#25\n\t"
  "add z20.s,z20.s,z21.s\n\t xar z23.s,z23.s,z20.s,#16\n\t add z22.s,z22.s,z23.s\n\t xar z21.s,z21.s,z22.s,#20\n\t"
  "add z20.s,z20.s,z21.s\n\t xar z23.s,z23.s,z20.s,#24\n\t add z22.s,z22.s,z23.s\n\t xar z21.s,z21.s,z22.s,#25\n\t"
  "subs %0,%0,#1\n\t bne 1b\n\tsmstop sm\n\t":"+r"(it)::
  "z0","z1","z2","z3","z4","z5","z6","z7","z8","z9","z10","z11","z12","z13","z14","z15","z16","z17","z18","z19","z20","z21","z22","z23","memory","cc");}
#define QRN (4*4.0*4.0)   /* vector-QRs/iter * 4 lanes  */
#define QRS (6*4.0*16.0)  /* vector-QRs/iter * 16 lanes */
static int64_t IT;
static void* wS(void*a){(void)a;SVEF(IT);return 0;}
static void* wN(void*a){(void)a;NEONF(IT);return 0;}
static double hybrid(int ns,int nn,int64_t it){
  IT=it; pthread_t t[32]; int k=0;
  uint64_t t0=nowi();
  for(int i=0;i<ns;i++) pthread_create(&t[k++],0,wS,0);
  for(int i=0;i<nn;i++) pthread_create(&t[k++],0,wN,0);
  for(int i=0;i<k;i++) pthread_join(t[i],0);
  uint64_t t1=nowi();
  double qr=(QRS*ns+QRN*nn)*(double)it;
  return qr/80.0*64.0/(double)(t1-t0);
}
int main(void){
  /* warm the machine up to steady clocks first */
  for(int i=0;i<3;i++) hybrid(2,8,2000000);
  int64_t it=12000000;
  printf("CORRECTED hybrid sweep (proper QR accounting, warmed, SSVE 6-chain / NEON 4-chain)\n");
  printf(" sme+neon |  GB/s\n");
  int cfg[][2]={{1,0},{2,0},{3,0},{4,0},{0,4},{0,8},{0,9},{0,10},{1,9},{2,8},{2,7},{3,7},{4,6},{1,8}};
  double best=0; int bs=0,bn=0, bestN=0; int bnn=0;
  for(unsigned i=0;i<sizeof(cfg)/sizeof(cfg[0]);i++){
    double g=0; for(int r=0;r<3;r++){double x=hybrid(cfg[i][0],cfg[i][1],it); if(x>g)g=x;}
    printf("   %d + %-2d  | %6.2f\n",cfg[i][0],cfg[i][1],g);
    if(g>best){best=g;bs=cfg[i][0];bn=cfg[i][1];}
    if(cfg[i][0]==0 && g>bestN){bestN=g;bnn=cfg[i][1];}
  }
  printf("\nBEST overall: %d SME + %d NEON = %.2f GB/s\n",bs,bn,best);
  printf("BEST NEON-only: 0 + %d = %.2f GB/s\n",bnn,(double)bestN);
  printf("Hybrid gain over best NEON-only: %+.1f%%\n",(best/bestN-1)*100);
  return 0;
}
