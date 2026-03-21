#include <cstddef>
#include <cstdint>
#include <limits.h>
#include "guest.h"

#include <x86gprintrin.h>

// From interrupts.asm
struct pvclock_vcpu_time_info *pvclock = (struct pvclock_vcpu_time_info*)0x3030;

uint64_t current_tsc(void) {
    uint64_t time = (__rdtsc() - pvclock->tsc_timestamp);
    int8_t tsc_shift = pvclock->tsc_shift;
    if (tsc_shift >= 0)
            time <<= tsc_shift;
    else
            time >>= -tsc_shift;
    return time;
}

// nanoseconds
uint64_t current_time(void) {
    uint64_t time = current_tsc();
    time = (time * pvclock->tsc_to_system_mul) >> 32;
    time = time + pvclock->system_time;
    return time;
}

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

#ifdef PRECISE_COVERAGE
extern "C" void log_coverage_trace(struct stack_frame *frame) {
    uint32_t trace_index = (uint32_t)(uintptr_t)vm64_coverage_state->trace_index;
    if(trace_index == PRECISE_TRACE_LOG_SIZE) {
        // We exhausted the ringbuffer, and need to VMExit so the VMM can drain it
        asm("out 33, eax" ::: "rax");
        trace_index = 0;
    }
    // Write the coverage item
    struct CoverageItem *new_item = (struct CoverageItem*)&vm64_coverage_state->trace_log[trace_index];
    // This is a per-vCPU adjusted timestamp. There is no way to get an equivalent timestamp
    // on the host! The rdtsc adjustment ends up being larger than KVM will next update
    // the system_time base, and the host can't get our tsc value to do its own adjustment.
    new_item->timestamp = current_time();
    new_item->rip = frame->rip - 1;
    new_item->rflags = frame->rflags;
    trace_index += sizeof(struct CoverageItem);
    vm64_coverage_state->trace_index = trace_index;
    return;
}
#endif

uint64_t register output asm("rdi");
extern "C" [[gnu::no_caller_saved_registers]] void _guest_bp_handler(struct stack_frame *frame) {
    size_t pc = frame->rip - 1;

    // Record coverage
    uint32_t mixed = fast_hash(pc) ^ (fast_hash(vm64_coverage_state->previous) << 1);
    vm64_coverage_state->previous = pc;
    uint32_t idx = mixed & ((COVERAGE_BITMAP_SIZE << CHAR_BIT)-1);
    vm64_coverage_state->coverage_map[idx >> CHAR_BIT] |= 1<<(idx & (CHAR_BIT-1));

    // If we're optimizing away reporting the coverage item via VMExit, but are
    // executing in "precise" mode, then we still need to record the coverage item
    // to a ringbuffer for full fidelity.
    if(PRECISE_COVERAGE) {
        log_coverage_trace(frame);
    }

    uint8_t *index = (uint8_t*)(pc + 1);
    if((*index & (uint8_t)COVERAGE_BITS) == COVERAGE_FRESH) {
        // VMM has to hook
        //frame->rdi = 0xf0f0f011;
        return;
    }

#ifdef COVERAGE_CMPCOV
    if((*index & COVERAGE_CMPCOV) == COVERAGE_CMPCOV) {
        // VMM has to emulate cmpcov operand
        return;
    }
#endif

    uint8_t page_index = *index & (uint8_t)~COVERAGE_BITS;
    uintptr_t inst_disp = pc % TRAMPOLINE_USABLE;
    auto page = vm64_coverage_state->trampolines[page_index];
    if(page == 0) {
        // VMM has to allocate trampoline page
        return;
    }
    size_t trampoline_code = (size_t)(page + inst_disp);
    size_t target = trampoline_code;

    if((*index & (uint8_t)COVERAGE_BITS) == COVERAGE_DYNCALL) {
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
