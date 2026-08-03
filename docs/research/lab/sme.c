#include <stdio.h>
#include <arm_sve.h>
__attribute__((target("sme2"))) __arm_locally_streaming
void f(uint64_t*o,const uint64_t*a,const uint64_t*b){
  svbool_t pg = svptrue_b64();
  svuint64_t x = svld1_u64(pg,a), y = svld1_u64(pg,b);
  svst1_u64(pg,o, svmul_u64_x(pg,x,y));
  svst1_u64(pg,o+8, svmulh_u64_x(pg,x,y));
}
int main(){ printf("svl bytes (streaming): see runtime\n"); return 0; }
