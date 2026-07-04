#include "tinycov.hpp"
#include <tinykvm/amd64/paging.hpp>
#include <tinykvm/amd64/amd64.hpp>
#include <tinykvm/amd64/gdt.hpp>
#include <tinykvm/amd64/idt.hpp>
#include <tinykvm/amd64/memory_layout.hpp>
#include <cstring>
#include <stdarg.h>
#include <sys/mman.h>
#include <bit>

namespace tinycov {

CoverageMachine::CoverageMachine(tinykvm::Machine& vm) : m_vm(vm) {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &m_capstone_handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone");
    }
    cs_option(m_capstone_handle, CS_OPT_DETAIL, CS_OPT_ON);

    if (getenv("OUTFILE")) {
        m_emit_file = fopen(getenv("OUTFILE"), "w");
    } else {
        m_emit_file = stdout;
    }
}

CoverageMachine::~CoverageMachine() {
    cs_close(&m_capstone_handle);
    if (m_emit_file && m_emit_file != stdout) {
        fclose(m_emit_file);
    }
}

void CoverageMachine::emit(const char *fmt, ...) {
#ifdef EMIT_COVERAGE
    va_list ap;

    // If we have precise coverage, then we also want to include the coverage trace entry
    // that this information is about.
#ifdef PRECISE_COVERAGE
    fprintf(m_emit_file, "%x ", (unsigned int)(m_collect_state->trace_index - sizeof(struct CoverageItem)));
#endif
    va_start(ap, fmt);
    vfprintf(m_emit_file, fmt, ap);
    va_end(ap);
#else
    (void)fmt;
#endif
}

TrampolinePage* CoverageMachine::allocate_trampoline() {
    uint64_t guest_addr = m_vm.mmap_allocate(TRAMPOLINE_SIZE, 0x7, false);
    tinykvm::page_at(m_vm.main_memory(), guest_addr, [] (uint64_t, uint64_t& entry, size_t) {
        // Make the page executable by the user (There is probably a better way to do this?)
        entry = (entry & ~PDE64_NX) | PDE64_DIRTY;
    });

    uintptr_t host_addr = (uintptr_t)m_vm.main_memory().at(guest_addr, TRAMPOLINE_SIZE);
    memset((char*)host_addr, 0, TRAMPOLINE_SIZE);

    TrampolinePage new_page = {
        .host_addr = host_addr,
        .guest_addr = guest_addr,
        .present = {},
        .index = m_next_index,
    };
    assert(!(m_next_index > (uint8_t)~COVERAGE_BITS));
    m_next_index += 1;
    m_trampoline.push_back(new_page);
    m_collect_state->trampolines[new_page.index] = (uintptr_t)guest_addr;
    return &m_trampoline.back();
}

TrampolinePage* CoverageMachine::find_trampoline(uint16_t disp, uint16_t len) {
    TrampolinePage *page = nullptr;
    for(auto& candidate : m_trampoline) {
        bool overlap = false;
        for(int i = 0; i < len && !overlap; i++) {
            if(candidate.present.contains((uint16_t)(disp + i))) {
                overlap = true;
                break;
            }
        }
        if(overlap) { continue; }
        page = &candidate;
        break;
    }
    if(!page) {
        // We fellthough without finding a free trampoline slot
        page = allocate_trampoline();
    }
    return page;
}

void CoverageMachine::hook_branch(uintptr_t pc, cs_insn *inst, cmpcov_state *cmpcov) {
    cmpcov->exit = pc;
    // Install coverage hook on a branch exit of a basic block
    struct trampoline_branch trampoline_code = {};
    uint16_t inst_disp = pc % TRAMPOLINE_USABLE;

    // Get the condition code from the original instruction
    uint8_t condition_code = 0;
    const char* mnemonic = inst->mnemonic;
    if (strcmp(mnemonic, "je") == 0 || strcmp(mnemonic, "jz") == 0) condition_code = 0x4;
    else if (strcmp(mnemonic, "jne") == 0 || strcmp(mnemonic, "jnz") == 0) condition_code = 0x5;
    else if (strcmp(mnemonic, "ja") == 0 || strcmp(mnemonic, "jnbe") == 0) condition_code = 0x7;
    else if (strcmp(mnemonic, "js") == 0) condition_code = 0x8;
    else if (strcmp(mnemonic, "jns") == 0) condition_code = 0x9;
    else if (strcmp(mnemonic, "jo") == 0) condition_code = 0x0;
    else if (strcmp(mnemonic, "jno") == 0) condition_code = 0x1;
    else if (strcmp(mnemonic, "jae") == 0 || strcmp(mnemonic, "jnb") == 0) condition_code = 0x3;
    else if (strcmp(mnemonic, "jb") == 0 || strcmp(mnemonic, "jnae") == 0) condition_code = 0x2;
    else if (strcmp(mnemonic, "jbe") == 0 || strcmp(mnemonic, "jna") == 0) condition_code = 0x6;
    else if (strcmp(mnemonic, "jg") == 0 || strcmp(mnemonic, "jnle") == 0) condition_code = 0xF;
    else if (strcmp(mnemonic, "jge") == 0 || strcmp(mnemonic, "jnl") == 0) condition_code = 0xD;
    else if (strcmp(mnemonic, "jl") == 0 || strcmp(mnemonic, "jnge") == 0) condition_code = 0xC;
    else if (strcmp(mnemonic, "jle") == 0 || strcmp(mnemonic, "jng") == 0) condition_code = 0xE;
    else if (strcmp(mnemonic, "jp") == 0 || strcmp(mnemonic, "jpe") == 0) condition_code = 0xA;
    // TODO: handle this properly
    else if (strcmp(mnemonic, "jrcxz") == 0 || strcmp(mnemonic, "jnrcxz") == 0) return;
    // lol no
    else if (strcmp(mnemonic, "xbegin") == 0) return;
    else {
        fprintf(stderr, "Unknown branch mnemonic: %s\n", mnemonic);
        assert(false);
    }

    TrampolinePage *page = find_trampoline(inst_disp, sizeof(trampoline_code));

    // We have page and it doesn't have any overlapping data
    // Write trampoline: jcc +5; jmp fallthrough; jmp target
    trampoline_code.jcc = 0x70 | condition_code;  // jcc +5
    trampoline_code.disp = 0x05;                   // offset +5
    // jmp fallthrough (5 bytes)
    uint64_t target_fallthrough = pc + inst->size;
    int64_t fallthrough_offset = target_fallthrough - (page->guest_addr + inst_disp + 7);
    trampoline_code.jcc_fallthrough = 0xE9;  // jmp rel32
    trampoline_code.disp_fallthrough = (int32_t)fallthrough_offset;
    // jmp target (5 bytes)
    uint64_t target_taken = inst->detail->x86.operands[0].imm;
    int64_t taken_offset = target_taken - (page->guest_addr + inst_disp + 12);
    trampoline_code.jcc_taken = 0xE9;  // jmp rel32
    trampoline_code.disp_taken = (int32_t)taken_offset;

    char* host_code = m_vm.main_memory().at(pc, 0x20);
    for(size_t i = 0; i < sizeof(trampoline_code); i++) {
        // Mark the bytes we will use as present
        page->present.add(inst_disp + i);
        // Write the trampoline
        *((char*)page->host_addr + inst_disp + i) = ((char*)&trampoline_code)[i];
    }
    for(int i = 0; i < inst->size; i++) {
        // NOP out the actual branch
        *(host_code + i) = 0x90;
    }
    // Replace first NOP with int3
    *(host_code + 0) = 0xcc;
    // Replace second byte with page selector, and mark it as fresh
    *(host_code + 1) = page->index | COVERAGE_FRESH;

#ifdef INSTRUMENT_CMPCOV
    if(INSTRUMENT_CMPCOV && cmpcov->present && cmpcov->has_reg) {
        m_cmpcov_operand[pc] = cmpcov->cmp;
        *(host_code + 1) = *(host_code + 1) | COVERAGE_CMPCOV;
    }
#endif
}

void CoverageMachine::hook_dyncall(uintptr_t pc, cs_insn *inst) {
    if(!INSTRUMENT_DYNCALL) {
        return;
    }
    // Install a coverage hook on a dynamic dispatch call exit of a basic block
    // Unlike branch tracing we can't use trampoline code, because then the
    // guest will observe the return address being the trampoline code instead
    // of the correct functions...which will break things such as C++ exception
    // unwinding.
    // Instead, we emulate some of the call in the kernel: we push the return address
    // from the replaced call instruction, and then redirect to the trampoline
    // which has the same dynamic dispatch but with a jump instead: this means
    // we don't need to figure out how to emulate the dynamic dispatch in the kernel.
    uint8_t trampoline_code[inst->size];
    memcpy(trampoline_code, inst->bytes, inst->size);

    uint16_t inst_disp = pc % TRAMPOLINE_USABLE;

    if(std::string(inst->op_str).find("rip") != std::string::npos) {
        return;
    }

    TrampolinePage *page = find_trampoline(inst_disp, sizeof(trampoline_code));

    bool hit = false;
    for(int i = 0; i < inst->size; i++) {
        // Look for the 0xFF opcode byte, which is after any prefix bytes.
        if(trampoline_code[i] != 0xFF) { continue; }
        uint8_t modrm = trampoline_code[i + 1];
        // Change the reg field of the ModR/M byte
        uint8_t reg = (modrm >> 3) & 0x07;
        if (reg != 2) continue; // Check it's a call (2)
        trampoline_code[i + 1] = (modrm & 0xC7) | (4 << 3);  // Clear reg field, set to jump (4)
        hit = true;
        break;
    }
    if (!hit) return;

    char* host_code = m_vm.main_memory().at(pc, 0x20);
    for(size_t i = 0; i < sizeof(trampoline_code); i++) {
        // Mark the bytes we will use as present
        page->present.add(inst_disp + i);
        // Write the trampoline
        *((char*)page->host_addr + inst_disp + i) = trampoline_code[i];
    }
    for(int i = 0; i < inst->size; i++) {
        // NOP out the actual branch
        *(host_code + i) = 0x90;
    }
    // Replace first NOP with int3
    *(host_code + 0) = 0xcc;
    // Replace second byte with page selector, and mark it as fresh and a dynamic dispatch
    *(host_code + 1) = page->index | COVERAGE_DYNCALL;
}

void CoverageMachine::hook_block(uintptr_t entry) {
    cs_insn *insn;
    size_t count;
    cmpcov_state cmpcov = { .present = false, .exit = 0, .cmp = 0, .has_reg = false, .reg1 = X86_REG_INVALID, .reg2 = X86_REG_INVALID };

    auto add_exit = [this](uint32_t dest) {
        if(dest == 0) { return false; }
        if(m_seen.contains(dest)) { return false; }
        m_seen.add(dest);
        m_blocks.push_back(dest);
        return true;
    };

    if(!m_seen.contains(entry)) {
        m_seen.add(entry);
        m_blocks.push_back(entry);
    } else {
        return;
    }

    cmpcov.present = false;
    while(m_blocks.size() > 0) {
        uintptr_t current_entry = m_blocks.back();
        m_blocks.pop_back();

        char *prog_mem = m_vm.main_memory().at(current_entry, 0x2000);
        size_t off = 0;
        bool hit_branch = false;
        while(off < (0x2000-12) && !hit_branch) {
            // disassemble one inst at a time until we hit the end of the basic block
            count = cs_disasm(m_capstone_handle, (const uint8_t*)(prog_mem + off), 0x1000, (uint64_t)(current_entry + off), 1, &insn);
            if (count > 0) {
                for (size_t j = 0; j < count && !hit_branch; j++) {
                    cs_insn *i = &(insn[j]);
                    if(strcmp(i->mnemonic, "int3") == 0) {
                        // One of our breakpoints, which we know was previously
                        // a basic block exit.
                        hit_branch = true;
                        break;
                    }
                    off += i->size;
                    if(strcmp(i->mnemonic, "ret") == 0) {
                        // End of basic block
                        hit_branch = true;
                        break;
                    }
#ifdef INSTRUMENT_CMPCOV
                    if(INSTRUMENT_CMPCOV && strcmp(i->mnemonic, "cmp") == 0) {
                        // Record last cmp as the cmpcov state for this block's exit
                        cmpcov = {
                            .present = true,
                            .exit = 0,
                            .cmp = i->address,
                        };
                        if(i->detail->x86.operands[1].type == X86_OP_IMM) {
                            m_dictionary.insert(i->detail->x86.operands[1].imm);
                        } else if(i->detail->x86.operands[1].size == 4 || i->detail->x86.operands[1].size == 8) {
                            // <16bit operands are small enough that a fuzzer will
                            // find them just by guessing fast enough to not matter.
                            cmpcov.has_reg = true;
                        }
                    }
#endif
                    cs_detail *detail = i->detail;
                    if (detail->groups_count > 0) {
                        for (int n = 0; n < detail->groups_count; n++) {
                            if(detail->groups[n] == CS_GRP_CALL) {
                                if(i->detail->x86.operands[0].type == X86_OP_IMM) {
                                    // Follow the branch
                                    add_exit(i->detail->x86.operands[0].imm);
                                    break;
                                } else {
                                    // Dynamic dispatch: for now just ignore it?
                                    hook_dyncall(i->address, i);
                                    hit_branch = true;
                                    break;
                                }
                            }
                            if(detail->groups[n] == CS_GRP_JUMP) {
                                if(i->detail->x86.operands[0].type == X86_OP_IMM) {
                                    auto dest = i->detail->x86.operands[0].imm;
                                    if(strcmp(i->mnemonic, "jmp") == 0) {
                                        // Just follow unconditional branch
                                        add_exit(dest);
                                        break;
                                    } else {
                                        // Follow both sides of the branch
                                        hook_branch(i->address, i, &cmpcov);
                                        hit_branch = true;
                                        break;
                                    }
                                } else {
                                    hit_branch = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                cs_free(insn, count);
            } else {
                break;
            }
            if(hit_branch) {
                cmpcov.present = false;
                break;
            }
        }
    }
}

void CoverageMachine::hit_fresh_branch(uintptr_t pc, uint8_t *selector) {
    // We hit the coverage hook of a block exit for the first time
    uint32_t index = *selector & (uint8_t)~COVERAGE_BITS;
    // Find the two successors of this coverage branch by looking at our own trampoline
    // instructions, which have displacements we can easily read out.
    uintptr_t inst_disp = pc % TRAMPOLINE_USABLE;
    auto page = m_trampoline.at(index);
    assert(page.present.contains(inst_disp));

    struct trampoline_branch *trampoline_code = (struct trampoline_branch*)(page.host_addr + inst_disp);

    int32_t fallthrough_offset = trampoline_code->disp_fallthrough;
    int32_t taken_offset = trampoline_code->disp_taken;

    uint32_t target_fallthrough = page.guest_addr + inst_disp + 7 + fallthrough_offset;
    uint32_t target_taken = page.guest_addr + inst_disp + 12 + taken_offset;

    *selector = *selector & ~COVERAGE_FRESH;

    hook_block(target_fallthrough);
    hook_block(target_taken);
}

uint64_t CoverageMachine::get_register_value(const tinykvm::tinykvm_x86regs *regs, x86_reg reg) {
    switch (reg) {
        case X86_REG_RAX: return regs->rax;
        case X86_REG_RBX: return regs->rbx;
        case X86_REG_RCX: return regs->rcx;
        case X86_REG_RDX: return regs->rdx;
        case X86_REG_RSI: return regs->rsi;
        case X86_REG_RDI: return regs->rdi;
        case X86_REG_RBP: return regs->rbp;
        case X86_REG_RSP: return regs->rsp;
        case X86_REG_R8:  return regs->r8;
        case X86_REG_R9:  return regs->r9;
        case X86_REG_R10: return regs->r10;
        case X86_REG_R11: return regs->r11;
        case X86_REG_R12: return regs->r12;
        case X86_REG_R13: return regs->r13;
        case X86_REG_R14: return regs->r14;
        case X86_REG_R15: return regs->r15;
        case X86_REG_RIP: return regs->rip;
        case X86_REG_EAX: return regs->rax & 0xFFFFFFFF;
        case X86_REG_EBX: return regs->rbx & 0xFFFFFFFF;
        case X86_REG_ECX: return regs->rcx & 0xFFFFFFFF;
        case X86_REG_EDX: return regs->rdx & 0xFFFFFFFF;
        case X86_REG_ESI: return regs->rsi & 0xFFFFFFFF;
        case X86_REG_EDI: return regs->rdi & 0xFFFFFFFF;
        case X86_REG_EBP: return regs->rbp & 0xFFFFFFFF;
        case X86_REG_ESP: return regs->rsp & 0xFFFFFFFF;
        case X86_REG_R8D:  return regs->r8 & 0xFFFFFFFF;
        case X86_REG_R9D:  return regs->r9 & 0xFFFFFFFF;
        case X86_REG_R10D: return regs->r10 & 0xFFFFFFFF;
        case X86_REG_R11D: return regs->r11 & 0xFFFFFFFF;
        case X86_REG_R12D: return regs->r12 & 0xFFFFFFFF;
        case X86_REG_R13D: return regs->r13 & 0xFFFFFFFF;
        case X86_REG_R14D: return regs->r14 & 0xFFFFFFFF;
        case X86_REG_R15D: return regs->r15 & 0xFFFFFFFF;
        case X86_REG_AL: return regs->rax & 0xFFFF;
        case X86_REG_BL: return regs->rbx & 0xFFFF;
        case X86_REG_CL: return regs->rcx & 0xFFFF;
        case X86_REG_DL: return regs->rdx & 0xFFFF;
        case X86_REG_AH: return regs->rax & 0xFFFF0000;
        case X86_REG_BH: return regs->rbx & 0xFFFF0000;
        case X86_REG_CH: return regs->rcx & 0xFFFF0000;
        case X86_REG_DH: return regs->rdx & 0xFFFF0000;
        default: return 0;
    }
}

int CoverageMachine::resolve_operand(cs_x86_op *op, tinykvm::tinykvm_x86regs *regs, uint64_t *target) {
    switch (op->type) {
        case X86_OP_REG:
            *target = get_register_value(regs, op->reg);
            return 0;
        case X86_OP_IMM:
            *target = op->imm;
            return 0;
        case X86_OP_MEM: {
            uint64_t addr = op->mem.disp;
            if (op->mem.base != X86_REG_INVALID)
                addr += get_register_value(regs, op->mem.base);
            if (op->mem.index != X86_REG_INVALID)
                addr += get_register_value(regs, op->mem.index) * op->mem.scale;
            memcpy(target, m_vm.main_memory().safely_at(addr, sizeof(*target)), sizeof(*target));
            return 0;
        }
        default: break;
    }
    return -1;
}

int CoverageMachine::resolve_target(cs_insn *insn, tinykvm::tinykvm_x86regs *regs, uint64_t *target) {
    cs_x86_op *op = &insn->detail->x86.operands[0];
    return resolve_operand(op, regs, target);
}

uintptr_t CoverageMachine::hit_dyncall(uintptr_t pc, uint8_t *code, uint8_t *selector) {
    (void)selector;
    auto guest_frame = m_vm.registers().rdi;
    auto host_frame = (struct stack_frame*)m_vm.main_memory().at(guest_frame, sizeof(struct stack_frame));
    // guest_rsp is the guest *kernel* stack. we need to get the guest user rsp
    // from the pushed exception.
    auto guest_user_rsp = host_frame->stack;
    // Push to the user stack
    guest_user_rsp = guest_user_rsp - sizeof(uintptr_t);
    auto host_ret = (uint64_t*)m_vm.main_memory().at(guest_user_rsp, sizeof(uintptr_t));
    *host_ret = pc + 2;
    host_frame->stack = guest_user_rsp;

    // ugh this doesn't even work well, because we can't resolve the call target to
    // follow and push the coverage frontier forward, or record in our coverage map...
    // TODO: jit an assembly stub in the trampoline pages to resolve the dyncall target?
    // idk what else we can do here unfortunately
    cs_insn *insn;
    assert(cs_disasm(m_capstone_handle, code, 0x20, pc, 1, &insn) == 1);

    auto regs = m_vm.registers();
    regs.rdi = host_frame->rdi;
    regs.rsp = guest_user_rsp;
    regs.rip = pc;
    uint64_t target = 0;
    assert(resolve_target(insn, &regs, &target) == 0);
    cs_free(insn, 1);

    emit("dyncall %p -> %p\n", (void*)pc, (void*)target);
    hook_block(target);
    return target;
}

void CoverageMachine::hit_cmpcov(tinykvm::tinykvm_x86regs *regs, uintptr_t comparison) {
    cs_insn *insn;
    uint8_t *code = (uint8_t*)m_vm.main_memory().at(comparison, 0x20);
    assert(cs_disasm(m_capstone_handle, code, 0x20, comparison, 1, &insn) == 1);

    uint64_t op0 = 0;
    uint64_t op1 = 0;
    assert(resolve_operand(&insn->detail->x86.operands[0], regs, &op0) == 0);
    assert(resolve_operand(&insn->detail->x86.operands[1], regs, &op1) == 0);
    cs_free(insn, 1);

    emit("cmpcov %p %llx %llx\n", (void*)comparison, op0, op1);
    m_dictionary.insert(op0);
    m_dictionary.insert(op1);
}

void CoverageMachine::drain_log() {
    if (!m_collect_state) return;
    uint32_t trace_index = (uint32_t)(uintptr_t)m_collect_state->trace_index;
    if(trace_index == 0) return;
    for(uint32_t i = 0; i < trace_index; i += sizeof(struct CoverageItem)) {
        struct CoverageItem item;
        m_vm.copy_from_guest(&item, (uintptr_t)m_collect_state->trace_log + i, sizeof(item));
        fprintf(m_emit_file, "drain %lx %lx %lx\n", (unsigned long)item.timestamp, (unsigned long)item.rip, (unsigned long)item.rflags);
    }
}

void CoverageMachine::on_output(tinykvm::vCPU& cpu, unsigned int io_port, unsigned int) {
    if(io_port == 0x21) { drain_log(); return; }
    if(io_port != 0x20) { return; }
    m_coverage_vmexit_count += 1;
    auto guest_frame = cpu.registers().rdi;
    auto host_frame = (struct stack_frame*)cpu.machine().main_memory().at(guest_frame, sizeof(struct stack_frame));
    uint64_t rflags = host_frame->rflags;
    size_t pc = host_frame->rip - 1;
    auto host_code = (char*)cpu.machine().main_memory().at(pc, 0x10);

    // Load trampoline page index
    uint8_t *index = (uint8_t*)(host_code + 1);
    // Check if this is the first time a coverage hook was hit, in which case
    // we need to push the coverage frontier forward
    if((*index & COVERAGE_FRESH) == COVERAGE_FRESH) {
        hit_fresh_branch(pc, index);
    }

    uint8_t page_index = *index & (uint8_t)~COVERAGE_BITS;
    uintptr_t inst_disp = pc % TRAMPOLINE_USABLE;
    auto page = m_trampoline.at(page_index);

    uint8_t *trampoline_code = (uint8_t*)(page.host_addr + inst_disp);
    uint32_t target = page.guest_addr + inst_disp;

    emit("%lx %lx\n", (unsigned long)pc, (unsigned long)rflags);

    // DYNCALL and CMPCOV are disjointa branch types
    if((*index & (uint8_t)COVERAGE_BITS) == COVERAGE_DYNCALL) {
        target = hit_dyncall(pc, trampoline_code, index);
    }
#ifdef INSTRUMENT_CMPCOV
    else if((*index & COVERAGE_CMPCOV) == COVERAGE_CMPCOV) {
        auto regs = cpu.registers();
        regs.rdi = host_frame->rdi;
        regs.rsp = host_frame->stack;
        regs.rip = pc;

        assert(m_cmpcov_operand.contains(pc));
        auto comparison = m_cmpcov_operand[pc];
        hit_cmpcov(&regs, comparison);
    }
#endif
    host_frame->rip = target;
}

bool CoverageMachine::on_page_fault(tinykvm::vCPU& cpu, tinykvm::Machine::address_t page) {
    uint64_t code;
    uint64_t rip;
    cpu.machine().unsafe_copy_from_guest(&code, cpu.registers().rsp+16, 8);
    if((code & 0x10) == 0) { return false; }
    cpu.machine().unsafe_copy_from_guest(&rip, cpu.registers().rsp+24, 8);
    bool unexec = false;
    if(m_unexec_pages.contains(page)) {
        m_unexec_pages.remove(page);
        hook_block(rip);
        tinykvm::page_at(cpu.machine().main_memory(), page,
                [&] (uint64_t, uint64_t& entry, size_t)
        {
            entry = (entry & ~PDE64_NX) | PDE64_DIRTY;
            unexec = true;
        }, true);
    }
    return unexec;
}

void CoverageMachine::on_mmap(tinykvm::vCPU& cpu, tinykvm::Machine::address_t addr, size_t length, int, int prot, int, tinykvm::Machine::address_t) {
    auto allocated = addr;
    if(allocated == 0) { allocated = cpu.registers().rax; }
    if(allocated == (size_t)MAP_FAILED) { return; }

    if(prot & PROT_EXEC) {
        m_unexec_pages.add(allocated);
        for(size_t i = 0; i < (length-1); i += PAGE_SIZE) {
            tinykvm::page_at(cpu.machine().main_memory(), allocated + i,
                    [] (uint64_t, uint64_t& entry, size_t)
            {
                entry = entry | PDE64_NX | PDE64_DIRTY;
            });
            (void)*cpu.machine().main_memory().safely_at(allocated + i, PAGE_SIZE);
            m_unexec_pages.add(allocated + i);
        }
    }
}

static void on_output_static(tinykvm::vCPU& cpu, unsigned int io_port, unsigned int val) {
    auto* cov = (CoverageMachine*)cpu.machine().get_userdata<CoverageMachine>();
    if (cov) {
        cov->on_output(cpu, io_port, val);
    }
}

static bool on_page_fault_static(tinykvm::vCPU& cpu, tinykvm::Machine::address_t addr) {
    auto* cov = (CoverageMachine*)cpu.machine().get_userdata<CoverageMachine>();
    if (cov) {
        return cov->on_page_fault(cpu, addr);
    }
    return false;
}

void CoverageMachine::install_hooks() {
    uint64_t start_address = m_vm.registers().rip;
    m_vm.set_userdata(this);

    if(UNEXEC_TRACING) {
        m_vm.set_mmap_callback([this] (tinykvm::vCPU& cpu, tinykvm::Machine::address_t addr, size_t length, int flags, int prot, int fd, tinykvm::Machine::address_t voff) {
            this->on_mmap(cpu, addr, length, flags, prot, fd, voff);
        });

        m_vm.set_page_fault_callback(on_page_fault_static);
    }

    m_collect_state_guest = m_vm.mmap_allocate(0x1000, 0x7, false);
    m_collect_state = (struct CollectorState *)m_vm.main_memory().at(m_collect_state_guest, sizeof(*m_collect_state));

    // Create coverage bitmap
    m_collect_state->coverage_map = (uintptr_t)m_vm.mmap_allocate(COVERAGE_BITMAP_SIZE, 0x7, false);
#ifdef PRECISE_COVERAGE
    // Create ringbuffer for precise coverage tracing in the guest
    m_collect_state->trace_log = (uintptr_t)m_vm.mmap_allocate(PRECISE_TRACE_LOG_SIZE, 0x7, false);
    m_collect_state->trace_index = 0;
#endif

    ((tinykvm::iasm_header*)m_vm.main_memory().at(
        m_vm.main_memory().physbase + tinykvm::INTR_ASM_ADDR))->vm64_coverage_state = m_collect_state_guest;

    m_vm.install_output_handler(on_output_static);

    // For debugging we occasionally want to pre-allocate all of the trampoline
    // pages, since otherwise dynamically mapped in user code will be at different
    // addresses and thus set different coverage bits.
    //for(int i = 0; i < 0x3f; i++) {
    //    allocate_trampoline();
    //}

    if(ENTRY_TRACING) {
        hook_block(start_address);
    }
}

void CoverageMachine::report() {
    drain_log();
    uint8_t* mem = (uint8_t *)m_vm.main_memory().at((uintptr_t)m_collect_state->coverage_map, COVERAGE_BITMAP_SIZE);
    uint32_t count = 0;
    for(int i = 0; i < COVERAGE_BITMAP_SIZE; i++) {
        count += std::popcount(mem[i]);
    }
    printf("Coverage Count: 0x%x\n", count);
    printf("VMExit Count: 0x%lx\n", m_coverage_vmexit_count);
#ifdef INSTRUMENT_CMPCOV
    if constexpr(INSTRUMENT_CMPCOV) {
        printf("Dictionary:");
        for(auto entry : m_dictionary) {
            printf(" %lx", (unsigned long)entry);
        }
        printf("\n");
    }
#endif
}

uint32_t CoverageMachine::coverage_count() const {
    uint8_t* mem = (uint8_t *)m_vm.main_memory().at((uintptr_t)m_collect_state->coverage_map, COVERAGE_BITMAP_SIZE);
    uint32_t count = 0;
    for(int i = 0; i < COVERAGE_BITMAP_SIZE; i++) {
        count += std::popcount(mem[i]);
    }
    return count;
}

} // namespace tinycov
