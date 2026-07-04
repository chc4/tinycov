#pragma once
#include <tinykvm/machine.hpp>
#define HOST 1
#include <tinykvm/amd64/builtin/guest.h>
#include <capstone/capstone.h>
#include <roaring.hh>
#include <vector>
#include <set>
#include <map>
#include <string>
#include <cstdio>

namespace tinycov {

struct TrampolinePage {
    uintptr_t host_addr;
    uintptr_t guest_addr;
    roaring::Roaring present;
    uint32_t index;
};

struct __attribute__((packed)) trampoline_branch {
    uint8_t jcc;
    uint8_t disp;

    uint8_t jcc_fallthrough;
    uint32_t disp_fallthrough;

    uint8_t jcc_taken;
    uint32_t disp_taken;
};

struct cmpcov_state {
    bool present;
    uintptr_t exit;
    uintptr_t cmp;
    bool has_reg;
    x86_reg reg1;
    x86_reg reg2;
};

class CoverageMachine {
public:
    CoverageMachine(tinykvm::Machine& vm);
    ~CoverageMachine();

    void install_hooks();
    void report();
    void drain_log();

    tinykvm::Machine& machine() { return m_vm; }

    // Coverage data accessors
    uint8_t* coverage_map(size_t&) const;
    uint32_t coverage_count() const;
    const roaring::Roaring& seen_blocks() const { return m_seen; }
    const std::set<uint64_t>& dictionary() const { return m_dictionary; }

private:
    tinykvm::Machine& m_vm;

    // State moved from static globals
    std::vector<TrampolinePage> m_trampoline;
    uint32_t m_next_index = 0;
    struct CollectorState *m_collect_state = nullptr;
    uint64_t m_collect_state_guest = 0;
    FILE* m_emit_file = nullptr;
    std::set<uint64_t> m_dictionary;
    std::map<uintptr_t, uintptr_t> m_cmpcov_operand;
    roaring::Roaring m_seen;
    std::vector<uintptr_t> m_blocks;
    roaring::Roaring m_unexec_pages;
    uint64_t m_coverage_vmexit_count = 0;

    csh m_capstone_handle;

    // Internal methods
    void emit(const char *fmt, ...);
    TrampolinePage* allocate_trampoline();
    TrampolinePage* find_trampoline(uint16_t disp, uint16_t len);
    void hook_branch(uintptr_t pc, cs_insn *inst, cmpcov_state *cmpcov);
    void hook_dyncall(uintptr_t pc, cs_insn *inst);
    void hook_block(uintptr_t entry);
    void hit_fresh_branch(uintptr_t pc, uint8_t *selector);
    uintptr_t hit_dyncall(uintptr_t pc, uint8_t *code, uint8_t *selector);
    void hit_cmpcov(tinykvm::tinykvm_x86regs *regs, uintptr_t comparison);

public:
    // Callback handlers
    void on_output(tinykvm::vCPU& cpu, unsigned int io_port, unsigned int val);
    bool on_page_fault(tinykvm::vCPU& cpu, tinykvm::Machine::address_t addr);
    void on_mmap(tinykvm::vCPU& cpu, tinykvm::Machine::address_t addr, size_t length, int flags, int prot, int fd, tinykvm::Machine::address_t voff);

private:
    // Helpers
    /**
     * Get register value from state
     */
    static uint64_t get_register_value(const tinykvm::tinykvm_x86regs *regs, x86_reg reg);
    /**
     * Calculate the concrete jump/call target given instruction and register state.
     *
     * @param insn Capstone instruction (must be call or jmp)
     * @param regs Register state
     * @param target Output: calculated target address
     * @param read_memory Callback to read memory (can be NULL if not needed)
     * @param user_data Passed to read_memory callback
     * @return 0 on success, -1 on error
     */
    int resolve_operand(cs_x86_op *op, tinykvm::tinykvm_x86regs *regs, uint64_t *target);
    int resolve_target(cs_insn *insn, tinykvm::tinykvm_x86regs *regs, uint64_t *target);
};

} // namespace tinycov
