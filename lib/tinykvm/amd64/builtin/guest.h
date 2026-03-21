#include <cstddef>
#include <cstdint>

// Coverage collection options
#define INSTRUMENT_DYNJUMP 0
#define INSTRUMENT_DYNCALL 1
//#define INSTRUMENT_CMPCOV 0
#define ENTRY_TRACING 1
#define UNEXEC_TRACING 1
#define EMIT_COVERAGE 1

// Trampoline selector bits
// We will never have a FRESH DYNJUMP, because dynamic dispatch hooks must always
// be considered fresh: we always need to try and follow the targets at runtime.
#define COVERAGE_FRESH (0x80) // Mark unhit branch hooks
//#define COVERAGE_DYNJUMP (0x40) // Mark dynamic dispatch jump instructions
#define COVERAGE_DYNCALL (0x40) // Mark dynamic dispatch call instructions
#ifdef INSTRUMENT_CMPCOV
#define COVERAGE_CMPCOV (0x20) // Mark dynamic dispatch jump instructions
#define COVERAGE_BITS (COVERAGE_FRESH | COVERAGE_DYNCALL | COVERAGE_CMPCOV)
#else
#define COVERAGE_BITS (COVERAGE_FRESH | COVERAGE_DYNCALL)
#endif
#define TRAMPOLINE_SIZE (0x1000) // Length of each trampoline page
static_assert(TRAMPOLINE_SIZE % 0x1000 == 0);
#define TRAMPOLINE_USABLE (TRAMPOLINE_SIZE - 12) // Number of bytes usable in each trampoline page
#define COVERAGE_BITMAP_SIZE (0x1000) // Number of bytes in the coverage bitmap

#ifdef HOST
#define guest(x) uintptr_t
#else
#define guest(x) x
#endif
// Coverage collection state that is memory mapped between the host and guest.
struct CollectorState {
    // ugh, we can't just share the std::vector because of vtables. this has a max
    // size of ~COVERAGE_BITS.
    guest(char*) trampolines[(0xff & ((uint8_t)~COVERAGE_BITS))];
    guest(uint8_t*) coverage_map;
    uint64_t previous;
};
static_assert(sizeof(struct CollectorState) < 0x1000);

struct stack_frame {
    size_t rdi;
    size_t rip;
    size_t cs;
    size_t rflags;
    size_t stack;
};
