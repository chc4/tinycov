#undef NDEBUG
#include <tinykvm/machine.hpp>
#include <tinykvm/common.hpp>
#include <tinykvm/memory.hpp>
#include <tinykvm/amd64/paging.hpp>
#include <tinykvm/amd64/amd64.hpp>
#include <tinykvm/amd64/idt.hpp>
#include <linux/kvm.h>
#include <tinykvm/amd64/gdt.hpp>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <set>
#include "assert.hpp"
#include "load_file.hpp"
#include "sys/mman.h"
#include <asm/processor-flags.h>

#include <capstone/capstone.h>
#include <roaring.hh>

#include <tinykvm/rsp_client.hpp>
#define HOST 1
#include <tinykvm/amd64/builtin/guest.h>

#define GUEST_MEMORY   0x80000000  /* 2GB memory */
#define GUEST_WORK_MEM 1024UL * 1024*1024 /* MB working mem */
#define INSTRUMENT_DYNJUMP 0
#define INSTRUMENT_DYNCALL 1
#define ENTRY_TRACING 1
// TODO: this is buggy and causes spurious crashes, i suspect due to falling through
// the end of hooked blocks to the next page which triggers a fault
#define UNEXEC_TRACING 1
//#define EMIT_COVERAGE 1
//#define DEBUG 1

#ifdef DEBUG
#define dprintf printf
#else
#define dprintf(...) ((void)0)
#endif


static uint64_t verify_exists(tinykvm::Machine& vm, const char* name)
{
    uint64_t addr = vm.address_of(name);
    if (addr == 0x0) {
//      fprintf(stderr, "Error: '%s' is missing\n", name);
//      exit(1);
    }
    return addr;
}

inline timespec time_now();
inline long nanodiff(timespec start_time, timespec end_time);

struct TrampolinePage {
    uintptr_t host_addr;
    uintptr_t guest_addr;
    roaring::Roaring present;
    uint32_t index;
};

static std::vector<struct TrampolinePage> trampoline = {};
static uint32_t next_index = 0;

static struct CollectorState *collect_state;
uint64_t collect_state_guest;

void dhexdump(tinykvm::vCPU& cpu, uintptr_t data, uintptr_t len) {
    char* mem = cpu.machine().main_memory().at(data, len);
    dprintf("%x: ", data);
    for(int i = 0; i < len; i++) {
        dprintf("%02x ", (unsigned char)mem[i]);
    }
    dprintf("\n");
}

void hexdump(tinykvm::vCPU& cpu, uintptr_t data, uintptr_t len) {
    char* mem = cpu.machine().main_memory().at(data, len);
    printf("%x: ", data);
    for(int i = 0; i < len; i++) {
        printf("%02x ", (unsigned char)mem[i]);
    }
    printf("\n");
}


struct TrampolinePage *allocate_trampoline(tinykvm::Machine& machine) {
    uint64_t guest_addr = machine.mmap_allocate(0x1000, 0x7, false);
    page_at(machine.main_memory(), guest_addr, [] (uint64_t addr, uint64_t& entry, size_t size) {
        // Make the page executable by the user (There is probably a better way to do this?)
        entry = entry & ~PDE64_NX | PDE64_DIRTY;
    });


    uintptr_t host_addr = (uintptr_t)machine.main_memory().at(guest_addr, 0x1000);
    memset((char*)host_addr, 0, 0x1000);
    dprintf("allocated new trampoline page @ h:%x g:%x\n", host_addr, guest_addr);
    struct TrampolinePage new_page = {
        .host_addr = host_addr,
        .guest_addr = guest_addr,
        .present = {},
        .index = next_index,
    };
    assert(next_index < 0x40);
    next_index += 1;
    trampoline.push_back(new_page);
    collect_state->trampolines[new_page.index] = guest_addr;
    return &trampoline.back();
}


struct TrampolinePage *find_trampoline(tinykvm::vCPU& cpu, uint16_t disp, uint16_t len) {
    struct TrampolinePage *page = nullptr;
    for(auto& candidate : trampoline) {
        bool overlap = false;
        for(int i = 0; i < len && !overlap; i++) {
            if(candidate.present.contains((uint16_t)(disp + i))) {
                dprintf("h:%x present %x\n", candidate.host_addr, disp + i);
                // Something already present in this page
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
        page = allocate_trampoline(cpu.machine());
    }
    return page;
}

static void hook_branch(tinykvm::vCPU& cpu, uintptr_t pc, cs_insn *inst) {
    // Install coverage hook on a branch exit of a basic block
    struct __attribute__((packed)) trampoline_bytes {
        uint8_t jcc;
        uint8_t disp;

        uint8_t jcc_fallthrough;
        uint32_t disp_fallthrough;

        uint8_t jcc_taken;
        uint32_t disp_taken;
    };
    static_assert(sizeof(struct trampoline_bytes) == 12);

    struct trampoline_bytes trampoline_code = {};
    dprintf("hooking @ %x\n", pc);
    uint16_t inst_disp = pc % TRAMPOLINE_SIZE;
    size_t start_page = (pc / TRAMPOLINE_SIZE);
    //assert(start_page == end_page);
    //if(start_page != end_page) {
    //    return;
    //}

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
        printf("Unknown branch mnemonic: %s\n", mnemonic);
        assert(false);
    }

    struct TrampolinePage *page = find_trampoline(cpu, inst_disp, sizeof(trampoline_code));

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

    dprintf("hook coverage @ %p -> %p, %p\n", pc, target_fallthrough, target_taken);

    int i;
    char* host_code = cpu.machine().main_memory().at(pc, 0x20);
    for(i = 0; i < sizeof(trampoline_code); i++) {
        // Mark the bytes we will use as present
        page->present.add(inst_disp + i);
        // Write the trampoline
        *((char*)page->host_addr + inst_disp + i) = ((char*)&trampoline_code)[i];
    }
    for(i = 0; i < inst->size; i++) {
        // NOP out the actual branch
        *(host_code + i) = 0x90;
    }
    // Replace first NOP with int3
    *(host_code + 0) = 0xcc;
    // Replace second byte with page selector, and mark it as fresh
    *(host_code + 1) = page->index | COVERAGE_FRESH;
    dprintf("marked present %x--%x\n", inst_disp, inst_disp + i);
}

static void hook_dyncall(tinykvm::vCPU& cpu, uintptr_t pc, cs_insn *inst) {
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

    dprintf("hooking dyncall @ %x: %s %s\n", pc, inst->mnemonic, inst->op_str);
    uint16_t inst_disp = pc % TRAMPOLINE_SIZE;
    //assert(start_page == end_page);
    //if(start_page != end_page) {
    //    return;
    //}

    if(std::string(inst->op_str).find("rip") != std::string::npos) {
        dprintf("rip-relative dyncall, bailing");
        return;
    }

    struct TrampolinePage *page = find_trampoline(cpu, inst_disp, sizeof(trampoline_code));

    bool hit = false;
    for(int i = 0; i < sizeof(trampoline_code); i++) {
        // Look for the 0xFF opcode byte, which is after any prefix bytes.
        if(trampoline_code[i] != 0xFF) { continue; }
        uint8_t modrm = trampoline_code[i + 1];
        // Change the reg field of the ModR/M byte
        uint8_t reg = (modrm >> 3) & 0x07;
        assert(reg == 2); // Check it's a call (2)
        trampoline_code[i + 1] = (modrm & 0xC7) | (4 << 3);  // Clear reg field, set to jump (4)
        hit = true;
        break;
    }
    assert(hit);

    char* host_code = cpu.machine().main_memory().at(pc, 0x20);
    for(int i = 0; i < sizeof(trampoline_code); i++) {
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
    dprintf("marked present %x--%x\n", inst_disp, inst_disp + (uint32_t)sizeof(trampoline_code));
    return;
}

static roaring::Roaring seen = {};
static std::vector<uintptr_t> blocks {};
static roaring::Roaring unexec_pages;
static void hook_block(tinykvm::vCPU& cpu, uintptr_t entry) {

    csh handle;
    cs_insn *insn;
    size_t count;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    auto add_exit = [](uint32_t dest) {
        if(dest == 0) { return false; }

        if(seen.contains(dest)) { return false; }
        seen.add(dest);
        blocks.push_back(dest);
        return true;
    };

    if(!seen.contains(entry)) {
        seen.add(entry);
        blocks.push_back(entry);
    } else {
        goto cleanup;
    }

    while(blocks.size() > 0) {
        uintptr_t entry = blocks.at(blocks.size() - 1);
        blocks.pop_back();
        dprintf("-- BLOCK %x\n", entry);
        char *prog_mem = cpu.machine().main_memory().at(entry, 0x2000);
        size_t off = 0;
        bool hit_branch = false;
        while(off < 0x2000 && !hit_branch) {
            if constexpr(UNEXEC_TRACING) {
                size_t inst_page = (entry + off) & ~(PAGE_SIZE-1);
                if(unexec_pages.contains(inst_page)) {
                    unexec_pages.remove(inst_page);
                    // When we get an unexec hit, we will start executing the start of a block. That block
                    // may cross into another page, however, and we also need to make it executable again
                    // so that we don't potentially treat the page boundary as the start of another basic block.
                    dprintf("hook_block unexec clear %p\n", entry + off);
                    page_at(cpu.machine().main_memory(), entry + off,
                            [&] (uint64_t addr, uint64_t& entry, size_t size)
                    {
                        entry = entry & ~PDE64_NX | PDE64_DIRTY;
                    }, true);
                }
            }
            // disassemble one inst at a time until we hit the end of the basic block
            count = cs_disasm(handle, (const uint8_t*)(prog_mem + off), 0x1000, (uint64_t)(uintptr_t)(entry + off), 1, &insn);
            if (count > 0) {
                assert(count == 1);
                size_t j;
                uintptr_t dest = 0;

                for (j = 0; j < count && !hit_branch; j++) {
                    cs_insn *i = &(insn[j]);
                    if(strcmp(i->mnemonic, "int3") == 0) {
                        // One of our breakpoints, which we know was previously
                        // a basic block exit.
                        dprintf("0x%"PRIx64":\t%s\n", i->address, "COV");
                        hit_branch = true;
                        break;
                    }
                    off += i->size;
                    dprintf("0x%"PRIx64":\t%s\t\t%s\n", i->address, i->mnemonic,
                            i->op_str);
                    if(strcmp(i->mnemonic, "ret") == 0) {
                        // End of basic block
                        hit_branch = true;
                        break;
                    }
                    cs_detail *detail = i->detail;
                    if (detail->groups_count > 0) {
                        dprintf("\tinstruction group: ");
                        for (int n = 0; n < detail->groups_count; n++) {
                            dprintf("%s ", cs_group_name(handle, detail->groups[n]));
                            if(detail->groups[n] == cs_group_type::CS_GRP_CALL) {
                                if(i->detail->x86.operands[0].type == X86_OP_IMM) {
                                    // Follow the branch
                                    auto dest = i->detail->x86.operands[0].imm;
                                    add_exit(dest);
                                    break;
                                } else {
                                    // Dynamic dispatch: for now just ignore it?
                                    hook_dyncall(cpu, i->address, i);
                                    hit_branch = true;
                                    break;
                                }
                            }
                            if(detail->groups[n] == cs_group_type::CS_GRP_JUMP) {
                                if(i->detail->x86.operands[0].type == X86_OP_IMM) {
                                    auto dest = i->detail->x86.operands[0].imm;
                                    dprintf(" x86_jmp! %x\n", dest);
                                    if(strcmp(i->mnemonic, "jmp") == 0) {
                                        // Just follow unconditional branch
                                        add_exit(dest);
                                        break;
                                    } else {
                                        // Follow both sides of the branch
                                        //add_exit(i->address + i->size);
                                        //add_exit(dest);
                                        hook_branch(cpu, i->address, i);
                                        hit_branch = true;
                                        break;
                                    }
                                } else {
                                    //hook_dynjump(cpu, i->address, i);
                                    //assert(false);
                                    hit_branch = true;
                                    break;
                                }
                            }
                        }
                        dprintf("\n");
                    }
                }

                cs_free(insn, count);
            } else {
                dprintf("ERROR: Failed to disassemble given code! final off: %llx (%lld)\n", off, off);
                break;
            }

            if(hit_branch) {
                break;
            }
        }
    }

cleanup:
    cs_close(&handle);
}

static void hit_fresh_branch(tinykvm::vCPU& cpu, uintptr_t pc, uint8_t *selector) {
    // We hit the coverage hook of a block exit for the first time
    uint32_t index = *selector & ~COVERAGE_FRESH;
    // Find the two successors of this coverage branch by looking at our own trampoline
    // instructions, which have displacements we can easily read out.
    uintptr_t inst_disp = pc % TRAMPOLINE_SIZE;
    auto page = trampoline.at(index);
    assert(page.present.contains(inst_disp));


    uint8_t (*trampoline_code)[12] = (uint8_t(*)[12])(page.host_addr + inst_disp);

    int32_t fallthrough_offset = *(int32_t*)&(*trampoline_code)[3];
    int32_t taken_offset = 0;
    memcpy(&taken_offset, &(*trampoline_code)[8], sizeof(taken_offset));

    uint32_t target_fallthrough = page.guest_addr + inst_disp + 7 + fallthrough_offset;
    uint32_t target_taken = page.guest_addr + inst_disp + 12 + taken_offset;
    dprintf("fresh coverage @ %p -> %p, %p\n", pc, target_fallthrough, target_taken);
    *selector = *selector & ~COVERAGE_FRESH;

    hook_block(cpu, target_fallthrough);
    hook_block(cpu, target_taken);
    return;
}

// Some Claude written slop to resolve dynamic jump targets
/**
 * Get register value from state
 */
uint64_t get_register_value(const tinykvm::tinykvm_x86regs *regs, x86_reg reg) {
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

        // 32-bit registers (zero-extended)
        case X86_REG_EAX: return regs->rax & 0xFFFFFFFF;
        case X86_REG_EBX: return regs->rbx & 0xFFFFFFFF;
        case X86_REG_ECX: return regs->rcx & 0xFFFFFFFF;
        case X86_REG_EDX: return regs->rdx & 0xFFFFFFFF;
        case X86_REG_ESI: return regs->rsi & 0xFFFFFFFF;
        case X86_REG_EDI: return regs->rdi & 0xFFFFFFFF;
        case X86_REG_EBP: return regs->rbp & 0xFFFFFFFF;
        case X86_REG_ESP: return regs->rsp & 0xFFFFFFFF;

        case X86_REG_INVALID:
        default:
            assert(false);
            return 0;
    }
}

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
typedef int (*read_memory_fn)(uint64_t address, void *buffer, size_t size, void *user_data);

int resolve_target(tinykvm::vMemory& memory, cs_insn *insn, tinykvm::tinykvm_x86regs *regs, uint64_t *target) {
    cs_x86_op *op = &insn->detail->x86.operands[0];
    dprintf("resolving dynamic target %s\n", insn->op_str);

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

            // Now read from memory at 'addr'
            *target = *(uint64_t*)memory.at(addr);  // or your memory reader
            return 0;
        }
    }
    assert(false);
    return -1;
}

static uintptr_t hit_dyncall(tinykvm::vCPU& cpu, uintptr_t pc, uint8_t *code, uint8_t *selector) {
    auto guest_frame = cpu.registers().rdi;
    auto host_frame = (struct stack_frame*)cpu.machine().main_memory().at(guest_frame, sizeof(struct stack_frame));
    // guest_rsp is the guest *kernel* stack. we need to get the guest user rsp
    // from the pushed exception.
    auto guest_user_rsp = host_frame->stack;
    dprintf("guest_user_rsp %p\n", guest_user_rsp);
    dhexdump(cpu, guest_user_rsp, 0x20);
    // Push to the user stack
    guest_user_rsp = guest_user_rsp - sizeof(uintptr_t);
    auto host_ret = (uint64_t*)cpu.machine().main_memory().at(guest_user_rsp, sizeof(uintptr_t));
    *host_ret = pc+2;
    host_frame->stack = guest_user_rsp;

    // ugh this doesn't even work well, because we can't resolve the call target to
    // follow and push the coverage frontier forward, or record in our coverage map...
    // TODO: jit an assembly stub in the trampoline pages to resolve the dyncall target?
    // idk what else we can do here unfortunately
    csh handle;
    cs_insn *insn;

    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    assert(cs_disasm(handle, code, 0x20, pc, 1, &insn) == 1);

    auto regs = cpu.registers();
    regs.rdi = host_frame->rdi;
    regs.rsp = guest_user_rsp;
    regs.rip = pc;
    uint64_t target = 0;
    assert(resolve_target(cpu.machine().main_memory(), insn, &regs, &target) == 0);
    cs_free(insn, 1);

#ifdef EMIT_COVERAGE
    printf("dyncall %p -> %p\n", pc, target);
#endif
    cs_close(&handle);
    hook_block(cpu, target);
    return target;
}

static uint64_t coverage_vmexit_count = 0;

static uint64_t install_coverage_hooks(tinykvm::Machine& machine) {
    uint64_t start_address = machine.registers().rip;
    dprintf("elf start @ %p, %p\n", start_address, machine.entry_address());
    char *entry_mem = machine.main_memory().at(start_address, sizeof(uint32_t));
    ////*((uint8_t*)entry_mem + 0) = 0x90;
    //*((uint8_t*)entry_mem + 1) = 0x90;
    //*((uint8_t*)entry_mem + 2) = 0x90;
    dprintf("bytes at start: %s\n", entry_mem);

    print_gdt_entries(machine.main_memory().at(machine.get_special_registers().gdt.base), 7);
    machine.print_exception_handlers();

    if(UNEXEC_TRACING) {
        // Force mmap to not allocate executable memory, so that we always catch the first
        // jumps to code pages at least
        machine.set_mmap_callback([] (tinykvm::vCPU& cpu, size_t addr, size_t length, int flags, int prot, int read_fd, size_t voff) {
            auto allocated = addr;
            if(allocated == 0) {allocated = cpu.registers().rax; }
            if(allocated == (size_t)MAP_FAILED) { return; }
            dprintf("mmap callback, %p %x\n", allocated, length);

            if(prot & PROT_EXEC) {
                unexec_pages.add(allocated);
                for(int i = 0; i < (length-1); i += 0x1000) {
                    page_at(cpu.machine().main_memory(), allocated + i,
                            [] (uint64_t addr, uint64_t& entry, size_t size)
                    {
                        entry = entry | PDE64_NX | PDE64_DIRTY;
                    });
                    (void)*cpu.machine().main_memory().safely_at(allocated + i, 0x1000);
                    unexec_pages.add(allocated + i);
                }
                dprintf("unexec %p\n", allocated);
            }
        });

        machine.set_page_fault_callback([] (tinykvm::vCPU& cpu, size_t page) {
            dprintf("page fault\n");
            bool unexec = false;
            auto address = cpu.get_special_registers().cr2;
            if(unexec_pages.contains(page)) {
                dprintf("unexec pf @ %x (%x)\n", page, address);
                unexec_pages.remove(page);
                hook_block(cpu, address);
            }
            page_at(cpu.machine().main_memory(), page,
                    [&] (uint64_t addr, uint64_t& entry, size_t size)
            {
                dprintf("pf entry = %x\n", entry);
                entry = entry & ~PDE64_NX | PDE64_DIRTY;
                unexec = true;
            }, true);

            return unexec;
        });
    }

    collect_state_guest = machine.mmap_allocate(0x1000, 0x7, false);
    collect_state = (struct CollectorState *)machine.main_memory().at(collect_state_guest,
        sizeof(*collect_state));
    dprintf("collector state @ g=%p s=%p\n", collect_state_guest, collect_state);

    // Create coverage bitmap
    collect_state->coverage_map = machine.mmap_allocate(COVERAGE_BITMAP_SIZE, 0x7, false);
    dprintf("coverage map @ %x\n", collect_state->coverage_map);

    ((tinykvm::iasm_header*)machine.main_memory().at(
        machine.main_memory().physbase + tinykvm::INTR_ASM_ADDR))->vm64_coverage_state = collect_state_guest;

    machine.install_output_handler([](tinykvm::vCPU& cpu, unsigned int io_port, unsigned int val) {
        if(io_port != 0x20) { return; }
        coverage_vmexit_count += 1;
        auto guest_frame = cpu.registers().rdi;
        auto host_frame = (struct stack_frame*)cpu.machine().main_memory().at(guest_frame, sizeof(struct stack_frame));
        dprintf("rdi=%x rip=%x cs=%x rflags=%x stack=%x\n", host_frame->rdi, host_frame->rip, host_frame->cs, host_frame->rflags, host_frame->stack);
        uint64_t rflags = host_frame->rflags;
        size_t pc = host_frame->rip - 1;
        auto host_code = (char*)cpu.machine().main_memory().at(pc, 0x10);
        dprintf("custom io handler, val=%llx\n", host_frame->rip);

        // Load trampoline page index
        uint8_t *index = (uint8_t*)(host_code + 1);
        // Check if this is the first time a coverage hook was hit, in which case
        // we need to push the coverage frontier forward
        if((*index & COVERAGE_BITS) == COVERAGE_FRESH) {
            hit_fresh_branch(cpu, pc, index);
            assert((*index & COVERAGE_FRESH) == 0);
        }

        uint8_t page_index = *index & ~COVERAGE_BITS;
        uintptr_t inst_disp = pc % TRAMPOLINE_SIZE;
        auto page = trampoline.at(page_index);
        assert(page.present.contains(inst_disp));

        dprintf("trampoline h:%x g:%x contains\n", page.host_addr, page.guest_addr);

        uint8_t *trampoline_code = (uint8_t*)(page.host_addr + inst_disp);
        uint32_t trampoline_code_bytes = 0;
        memcpy(&trampoline_code_bytes, trampoline_code, sizeof(trampoline_code_bytes));
        dprintf("pc=%p inst=%x\n", pc, trampoline_code_bytes);
        uint32_t target = page.guest_addr + inst_disp;

#ifdef EMIT_COVERAGE
        printf("%x %x\n", pc, rflags);
#endif

        if((*index & COVERAGE_BITS) == COVERAGE_DYNCALL) {
            target = hit_dyncall(cpu, pc, trampoline_code, index);
        } else if((*index & COVERAGE_BITS) == COVERAGE_DYNJUMP) {
            // TODO: INSTRUMENT_DYNJUMP
            assert(false);
        }

        host_frame->rip = target;

        return;
    });

    // For debugging we occasionally want to pre-allocate all of the trampoline
    // pages, since otherwise dynamically mapped in user code will be at different
    // addresses and thus set different coverage bits.
    //for(int i = 0; i < 0x3f; i++) {
    //    allocate_trampoline(machine);
    //}

    if(ENTRY_TRACING) {
        hook_block(machine.cpu(), start_address);
    }

    return 0;
}

void coverage_report(tinykvm::Machine& machine) {
    hexdump(machine.cpu(), collect_state->coverage_map, COVERAGE_BITMAP_SIZE);
    uint8_t* mem = (uint8_t *)machine.main_memory().at(collect_state->coverage_map, COVERAGE_BITMAP_SIZE);
    uint32_t count = 0;
    for(int i = 0; i < COVERAGE_BITMAP_SIZE; i++) {
        count += std::popcount(mem[i]);
    }
    printf("Coverage Count: 0x%x\n", count);
    printf("VMExit Count: 0x%x\n", coverage_vmexit_count);
}


int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "Missing argument: 64-bit ELF binary\n");
        exit(1);
    }
    std::vector<uint8_t> binary;
    std::vector<std::string> args;
    std::string filename = argv[1];
    binary = load_file(filename);

    const tinykvm::DynamicElf dyn_elf = tinykvm::is_dynamic_elf(
        std::string_view{(const char*)binary.data(), binary.size()});
    if (dyn_elf.is_dynamic) {
        // Add ld-linux.so.2 as first argument
        static const std::string ld_linux_so = "/lib64/ld-linux-x86-64.so.2";
        binary = load_file(ld_linux_so);
        args.push_back(ld_linux_so);
    }

    for (int i = 1; i < argc; i++)
    {
        args.push_back(argv[i]);
    }

    tinykvm::Machine::init();

    tinykvm::Machine::install_unhandled_syscall_handler(
    [] (tinykvm::vCPU& cpu, unsigned scall) {
        switch (scall) {
            case 0x10000:
                cpu.stop();
                break;
            case 0x10001:
                throw "Unimplemented";
            case 0x10707:
                throw "Unimplemented";
            default:
                printf("Unhandled system call: %u\n", scall);
                auto regs = cpu.registers();
                regs.rax = -ENOSYS;
                cpu.set_registers(regs);
        }
    });

    const std::vector<tinykvm::VirtualRemapping> remappings {
        {
            .phys = 0x0,
            .virt = 0xC000000000,
            .size = 512ULL << 20,
        }
    };

    /* Setup */
    const tinykvm::MachineOptions options {
        .max_mem = GUEST_MEMORY,
        .max_cow_mem = GUEST_WORK_MEM,
        .reset_free_work_mem = 0,
        .vmem_base_address = uint64_t(getenv("UPPER") != nullptr ? 0x40000000 : 0x0),
        .remappings {remappings},
        .verbose_loader = true,
        .hugepages = (getenv("HUGE") != nullptr),

        // For NX based basic block discovery, having hugepages means we miss
        // many more other blocks once we trap one page.
        //.split_hugepages = true,
        .split_all_hugepages_during_loading = true,

        .relocate_fixed_mmap = (getenv("GO") == nullptr),
        .executable_heap = dyn_elf.is_dynamic,
    };
    tinykvm::Machine master_vm {binary, options};
    //master_vm.set_verbose_mmap_syscalls(true);
    //master_vm.set_verbose_system_calls(true);

    std::string cwd;
    {
        char buf[PATH_MAX];
        if (getcwd(buf, sizeof(buf)) != nullptr)
            cwd = buf;
    }
    master_vm.fds().set_current_working_directory(cwd.c_str());

    //master_vm.print_pagetables();
    if (dyn_elf.is_dynamic) {
        static const std::vector<std::string> allowed_readable_paths({
            argv[1],
            // Add all common standard libraries to the list of allowed readable paths
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "/lib/x86_64-linux-gnu/libgcc_s.so.1",
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib/x86_64-linux-gnu/libm.so.6",
            "/lib/x86_64-linux-gnu/libpthread.so.0",
            "/lib/x86_64-linux-gnu/libdl.so.2",
            "/lib/x86_64-linux-gnu/libstdc++.so.6",
            "/lib/x86_64-linux-gnu/librt.so.1",
            "/lib/x86_64-linux-gnu/libz.so.1",
            "/lib/x86_64-linux-gnu/libexpat.so.1",
            "/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v2/libstdc++.so.6",
            "/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libstdc++.so.6",
            "/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v4/libstdc++.so.6",
        });

        auto translate = [](tinykvm::Machine& machine, std::string& path) {
            if(path.find("/proc/self/fd/") != std::string::npos) {
                uint64_t fd = std::stoi(path.substr(14));
                fd = machine.fds().translate(fd);
                path.assign(std::string("/proc/self/fd/"));
                path.append(std::to_string(fd));
                dprintf("new path %s\n", path.c_str());
                return true;
            }
            return false;
        };

        master_vm.fds().set_open_readable_callback(
            [&] (std::string& path) -> bool {
            if(getenv("ALL_PATHS")) { translate(master_vm, path); return true; }
                return std::find(allowed_readable_paths.begin(),
                    allowed_readable_paths.end(), path) != allowed_readable_paths.end();
            }
        );
        master_vm.fds().set_open_writable_callback(
            [&] (std::string& path) -> bool {
            dprintf("open_writable callback for %s\n", path.c_str());
            if(getenv("ALL_PATHS")) { return true; }
            return false;
            }
        );
        master_vm.fds().set_resolve_symlink_callback(
            [&] (std::string& path) -> bool {
            dprintf("resolve_symlink callback for %s\n", path.c_str());
            if(getenv("ALL_PATHS")) {
                translate(master_vm, path);
                return false;
            } else {
                return false;
            }
        });
    }

    master_vm.setup_linux(
        args,
        {"LC_TYPE=C", "LC_ALL=C", "USER=root", "LD_BIND_NOW=1"});

    if(getenv("COVERAGE")) {
        install_coverage_hooks(master_vm);
    }

    const auto rsp = master_vm.stack_address();

    uint64_t call_addr = verify_exists(master_vm, "my_backend");

    /* Remote debugger session */
    if (getenv("DEBUG"))
    {
        auto* vm = &master_vm;
        tinykvm::tinykvm_x86regs regs;

        if (getenv("VMCALL")) {
            master_vm.run();
        }
        if (getenv("FORK")) {
            master_vm.prepare_copy_on_write();
            vm = new tinykvm::Machine {master_vm, options};
            vm->setup_call(regs, call_addr, rsp);
            vm->set_registers(regs);
        } else if (getenv("VMCALL")) {
            master_vm.setup_call(regs, call_addr, rsp);
            master_vm.set_registers(regs);
        }

        tinykvm::RSP server {filename, *vm, 2159};
        printf("Waiting for connection localhost:2159...\n");
        auto client = server.accept();
        if (client != nullptr) {
            /* Debugging session of _start -> main() */
            printf("Connected\n");
            try {
                //client->set_verbose(true);
                while (client->process_one());
            } catch (const tinykvm::MachineException& e) {
                printf("EXCEPTION %s: %lu\n", e.what(), e.data());
                vm->print_registers();
            }
        } else {
            /* Resume execution normally */
            vm->run();
        }
        /* Exit after debugging */
        return 0;
    }

    asm("" ::: "memory");
    auto t0 = time_now();
    asm("" ::: "memory");

    /* Normal execution of _start -> main() */
    try {
        master_vm.run();
    } catch (const tinykvm::MachineException& me) {
        master_vm.print_registers();
        fprintf(stderr, "Machine exception: %s  Data: 0x%lX\n", me.what(), me.data());
        throw;
    } catch (...) {
        master_vm.print_registers();
        throw;
    }

    asm("" ::: "memory");
    auto t1 = time_now();
    asm("" ::: "memory");

    if (call_addr == 0x0) {
        double t = nanodiff(t0, t1) / 1e9;
        printf("Time: %fs Return value: %ld\n", t, master_vm.return_value());
        if(getenv("COVERAGE")) {
            coverage_report(master_vm);
        }
        return 0;
    }

    /* Fork master VM */
    master_vm.prepare_copy_on_write();
    tinykvm::Machine vm{master_vm, options};

    /* Make a VM function call */
    tinykvm::tinykvm_regs regs;
    vm.setup_call(regs, call_addr, rsp);
    //regs.rip = vm.entry_address_if_usermode();
    vm.set_registers(regs);
    printf("Calling fork at 0x%lX\n", call_addr);
    vm.run(8.0f);

    /* Re-run */
    //vm.reset_to(master_vm, options);

    vm.setup_call(regs, call_addr, rsp);
    //regs.rip = vm.entry_address_if_usermode();
    vm.set_registers(regs);
    printf("Calling fork at 0x%lX\n", call_addr);
    vm.run(8.0f);
}

timespec time_now()
{
    timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return t;
}
long nanodiff(timespec start_time, timespec end_time)
{
    return (end_time.tv_sec - start_time.tv_sec) * (long)1e9 + (end_time.tv_nsec - start_time.tv_nsec);
}
