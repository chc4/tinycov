#include <cstddef>
#include <cstdint>
#include <limits.h>

#include "guest.h"

uint8_t *bitmap = (uint8_t*)0x20a01000;
// Compilers will attempt to align branches on i-cache boundaries to avoid Intel
// errata and to optimize some uop cache cases. We use a single fast-hash round
// as a mix function to try and spread the coverage item back out to the low bits.
uint64_t fast_hash(uint64_t h) {
    h ^= h >> 23;
    h *= 0x2127599bf4325c37ULL;
    h ^= h >> 47;
    return h;
}

extern "C" [[gnu::no_caller_saved_registers]] void _guest_bp_handler(struct stack_frame *frame) {
    uint32_t mixed = fast_hash(frame->rip);
    //uint32_t mixed = frame->rip;
    uint32_t idx = mixed & (BITMAP_SIZE-1);
    bitmap[idx >> CHAR_BIT] |= 1<<(idx & (CHAR_BIT-1));
    (void)frame->stack;

    //frame->rdi = 0xbadc0de;
    //asm("mov rdi, %0;\n out 32, eax" :: "r"(frame) : "rdi", "rax");
    return;
}
