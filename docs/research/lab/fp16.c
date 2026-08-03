#include <stdio.h>
int main(void){
  // largest consecutive integer exactly representable in fp16
  __fp16 x=0; int last=0;
  for(int i=0;i<70000;i++){ x=(__fp16)i; if((int)(float)x!=i){ last=i; break; } }
  printf("first integer NOT exact in fp16: %d\n", last);
  // XOR emulation a+b-2ab on 0/1 in fp16
  int ok=1;
  for(int a=0;a<2;a++) for(int b=0;b<2;b++){
    __fp16 fa=a, fb=b;
    __fp16 r=(__fp16)((float)fa+(float)fb-2.0f*(float)fa*(float)fb);
    if((int)(float)r != (a^b)) ok=0;
    printf("  xor(%d,%d) via a+b-2ab in fp16 = %d (expect %d)\n",a,b,(int)(float)r,a^b);
  }
  printf("fp16 bitsliced XOR exact: %s\n", ok?"YES":"NO");
  return 0;
}
