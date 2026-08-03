#include "poll.h"
int poll_u32(volatile uint32_t *p, uint32_t want, uint64_t maxspin) {
    for (uint64_t i = 0; i < maxspin; i++) {
        if (*p == want) return 1;
        __asm__ __volatile__("yield" ::: "memory");
    }
    return (*p == want);
}
