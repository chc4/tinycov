#include <cstddef>
#include <cstdint>
#include <limits.h>

#include "guest.h"

struct CollectorState *state = (struct CollectorState*)0x20a00000;
// Compilers will attempt to align branches on i-cache boundaries to avoid Intel
// errata and to optimize some uop cache cases. We use a single fast-hash round
// as a mix function to try and spread the coverage item back out to the low bits.
uint64_t fast_hash(uint64_t h) {
    h ^= h >> 23;
    h *= 0x2127599bf4325c37ULL;
    h ^= h >> 47;
    return h;
}

uint64_t register output asm("rdi");
extern "C" [[gnu::no_caller_saved_registers]] void _guest_bp_handler(struct stack_frame *frame) {
    size_t pc = frame->rip - 1;

    // Record coverage
    uint32_t mixed = fast_hash(pc);
    uint32_t idx = mixed & (BITMAP_SIZE-1);
    state->coverage_map[idx >> CHAR_BIT] |= 1<<(idx & (CHAR_BIT-1));

    uint8_t *index = (uint8_t*)(pc + 1);
    if((*index & COVERAGE_BITS) == COVERAGE_FRESH) {
        // VMM has to hook
        //frame->rdi = 0xf0f0f011;
        return;
    }

    uint8_t page_index = *index & ~COVERAGE_BITS;
    uintptr_t inst_disp = pc % TRAMPOLINE_SIZE;
    auto page = state->trampolines[page_index];
    if(page == 0) {
        // VMM has to allocate trampoline page
        frame->rdi = 0xf0f0f022;
        return;
    }
    size_t trampoline_code = (size_t)(page + inst_disp);
    frame->rip = trampoline_code;
    output = 0;
    return;
}
