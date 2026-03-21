#include <cstddef>
#include <cstdint>

// Coverage collection options
#define INSTRUMENT_DYNJUMP 0 // Instrument and trace coverage through dynamic jump instructions
#define INSTRUMENT_DYNCALL 1 // Instrument and trace coverage through dynamic call instructions
//#define INSTRUMENT_CMPCOV 0 // If 1, instrument CMP+JCC branches to record the operand values for magic byte dictionary construction
#define OPTIMIZE_VMEXIT 1 // If 1, the guest kernel will handle some coverage callbacks without vmexits.
#define PRECISE_COVERAGE 1 // If defined and 1, the guest kernel will record a precise coverage trace even when optimizing away VMExits.
#define ENTRY_TRACING 1 // If defined, initially start tracing coverage from the ELF entrypoint
#define UNEXEC_TRACING 1 // If 1, initially all mmap code pages non-executable and trace coverage the first time they are executed from.
#define EMIT_COVERAGE 1 // If defined and 1, printf the coverage trace to stdout during execution.

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
static_assert(COVERAGE_BITMAP_SIZE % 0x1000 == 0);
#define PRECISE_TRACE_LOG_SIZE (0x3000) // Number of bytes in the precise coverage trace ringbuffer
static_assert(PRECISE_TRACE_LOG_SIZE % 0x1000 == 0);

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
#ifdef PRECISE_COVERAGE
    guest(char *) trace_log;
    uint32_t trace_index;
#endif
};
static_assert(sizeof(struct CollectorState) < 0x1000);

struct stack_frame {
    size_t rdi;
    size_t rip;
    size_t cs;
    size_t rflags;
    size_t stack;
};

struct CoverageItem {
    size_t timestamp;
    uintptr_t rip;
    size_t rflags;
    uint32_t padding;
};
static_assert(PRECISE_TRACE_LOG_SIZE % sizeof(struct CoverageItem) == 0);

struct pvclock_vcpu_time_info {
      uint32_t   version;
      uint32_t   pad0;
      uint64_t   tsc_timestamp;
      uint64_t   system_time;
      uint32_t   tsc_to_system_mul;
      int8_t     tsc_shift;
      uint8_t    flags;
      uint8_t    pad[2];
} __attribute__((__packed__));

