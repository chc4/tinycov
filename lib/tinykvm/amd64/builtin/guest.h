#include <cstddef>
#include <cstdint>

// Trampoline selector bits
// We will never have a FRESH DYNJUMP, because dynamic dispatch hooks must always
// be considered fresh: we always need to try and follow the targets at runtime.
#define COVERAGE_FRESH (0x80) // Mark unhit branch hooks
//#define COVERAGE_DYNJUMP (0x40) // Mark dynamic dispatch jump instructions
#define COVERAGE_CMPCOV (0x20) // Mark dynamic dispatch jump instructions
#define COVERAGE_DYNCALL (0x40) // Mark dynamic dispatch call instructions
#define COVERAGE_BITS (COVERAGE_FRESH | COVERAGE_CMPCOV | COVERAGE_DYNCALL)
#define TRAMPOLINE_SIZE (0x1000 - 12) // Number of bytes in each trampoline page
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
    guest(char*) trampolines[0x3f];
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
