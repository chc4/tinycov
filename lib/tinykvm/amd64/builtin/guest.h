#include <cstddef>
#include <cstdint>

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
};
static_assert(sizeof(struct CollectorState) < 0x1000);

struct stack_frame {
    size_t rdi;
    size_t rip;
    size_t cs;
    size_t rflags;
    size_t stack;
};
#define BITMAP_SIZE (0x1000 << CHAR_BIT)
