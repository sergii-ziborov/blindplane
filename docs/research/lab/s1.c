#include <stdio.h>
#include <stdint.h>
__attribute__((target("sme"))) __arm_locally_streaming
static uint64_t get_svl(void) {
    uint64_t v; __asm__ volatile("rdsvl %0, #1" : "=r"(v)); return v;
}
int main(void){ setbuf(stdout,NULL); printf("entering streaming mode...\n");
  uint64_t v = get_svl(); printf("SVL bytes = %llu (%llu bits)\n", v, v*8); return 0; }
