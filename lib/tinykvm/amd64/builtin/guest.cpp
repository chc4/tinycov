#include <cstddef>
#include <cstdint>
#include <limits.h>

#include "guest.h"

#define OPTIMIZE_VMEXIT 1

extern struct CollectorState *vm64_coverage_state;
// Compilers will attempt to align branches on i-cache boundaries to avoid Intel
// errata and to optimize some uop cache cases. We use a single fast-hash round
// as a mix function to try and spread the coverage item back out to the low bits.
uint64_t fast_hash(uint64_t h) {
    h ^= h >> 23;
    h *= 0x2127599bf4325c37ULL;
    h ^= h >> 47;
    return h;
}

void crash_helper(struct stack_frame *frame, uint64_t tombstone) {
    frame->rdi = tombstone;
    frame->rip = 0xbadc0de;

    return;
}

uint64_t register output asm("rdi");
extern "C" [[gnu::no_caller_saved_registers]] void _guest_bp_handler(struct stack_frame *frame) {
    size_t pc = frame->rip - 1;

    // Record coverage
    uint32_t mixed = fast_hash(pc) ^ (fast_hash(vm64_coverage_state->previous) << 1);
    vm64_coverage_state->previous = pc;
    uint32_t idx = mixed & ((COVERAGE_BITMAP_SIZE << CHAR_BIT)-1);
    vm64_coverage_state->coverage_map[idx >> CHAR_BIT] |= 1<<(idx & (CHAR_BIT-1));

    uint8_t *index = (uint8_t*)(pc + 1);
    if((*index & COVERAGE_BITS) == COVERAGE_FRESH) {
        // VMM has to hook
        //frame->rdi = 0xf0f0f011;
        return;
    }

    if((*index & COVERAGE_CMPCOV) == COVERAGE_CMPCOV) {
        // VMM has to emulate cmpcov operand
        return;
    }

    uint8_t page_index = *index & ~COVERAGE_BITS;
    uintptr_t inst_disp = pc % TRAMPOLINE_SIZE;
    auto page = vm64_coverage_state->trampolines[page_index];
    if(page == 0) {
        // VMM has to allocate trampoline page
        return;
    }
    size_t trampoline_code = (size_t)(page + inst_disp);
    size_t target = trampoline_code;

    if((*index & COVERAGE_BITS) == COVERAGE_DYNCALL) {
        // Have to emulate DYNCALL in the VMM
        // TODO: we can instead JIT the DYNCALL emulation to the trampoline so we
        // don't need to take a VMExit
        return;
    }

    if(OPTIMIZE_VMEXIT) {
        frame->rip = trampoline_code;
        output = 0;
    }
    return;
}
