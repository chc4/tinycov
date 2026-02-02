#include <tinykvm/machine.hpp>
#include <tinykvm/common.hpp>
#include <tinykvm/memory.hpp>
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

#include <tinykvm/rsp_client.hpp>
#define GUEST_MEMORY   0x80000000  /* 2GB memory */
#define GUEST_WORK_MEM 1024UL * 1024*1024 /* MB working mem */

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
    std::set<uint16_t> present;
    uint32_t index;
};

static std::vector<struct TrampolinePage> trampoline = {};
static uint32_t next_index = 0;
static void hook_branch(tinykvm::vCPU& cpu, uintptr_t pc, cs_insn *inst) {
    dprintf("hooking @ %x\n", pc);
    uintptr_t inst_disp = pc % 0x1000;
    size_t start_page = (pc / 0x1000);
    size_t end_page = ((pc + inst->size) / 0x1000);
    assert(start_page == end_page);

    struct TrampolinePage *page = nullptr;

    for(auto& candidate : trampoline) {
        bool overlap = false;
        for(int i = 0; i < inst->size && !overlap; i++) {
            if(candidate.present.contains((uint16_t)(inst_disp + i))) {
                dprintf("h:%x present %x\n", candidate.host_addr, inst_disp + i);
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
        uint64_t guest_addr = cpu.machine().mmap_allocate(0x1000, PROT_EXEC, false);
        uintptr_t host_addr = (uintptr_t)cpu.machine().main_memory().at(guest_addr, 0x1000);
        memset((char*)host_addr, 0, 0x1000);
        dprintf("allocated new trampoline page @ h:%x g:%x\n", host_addr, guest_addr);
        struct TrampolinePage new_page = {
            .host_addr = host_addr,
            .guest_addr = guest_addr,
            .present = {},
            .index = next_index,
        };
        next_index += 1;
        trampoline.push_back(new_page);
        page = &trampoline.back();
    }

    // We have page and it doesn't have any overlapping data
    int i;
    char* host_code = cpu.machine().main_memory().at(pc, 0x20);
    for(i = 0; i < inst->size; i++) {
        // Mark the bytes we will use as present
        page->present.insert(inst_disp + i);
        // Write the original instruction
        *((char*)page->host_addr + inst_disp + i) = *(host_code + i);
        // NOP out the actual branch
        *(host_code + i) = 0x90;
    }
    // Replace first NOP with int3
    *(host_code + 0) = 0xcc;
    // Replace second byte with page selector
    *(host_code + 1) = page->index;
    dprintf("marked present %x--%x\n", inst_disp, inst_disp + i);


}

static void hook_block(tinykvm::vCPU& cpu, uintptr_t entry) {

    csh handle;
    cs_insn *insn;
    size_t count;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    std::set<uintptr_t> seen {};
    std::vector<uintptr_t> blocks {};
    seen.insert(entry);
    blocks.push_back(entry);
    while(blocks.size() > 0) {
        uintptr_t entry = blocks.at(blocks.size() - 1);
        blocks.pop_back();
        dprintf("-- BLOCK %x\n", entry);
        char *prog_mem = cpu.machine().main_memory().at(entry, 0x2000);
        size_t off = 0;
        bool hit_branch = false;
        while(off < 0x2000 && !hit_branch) {
            // disassemble one inst at a time until we hit the end of the basic block
            count = cs_disasm(handle, (const uint8_t*)(prog_mem + off), 0x200, (uint64_t)(uintptr_t)(entry + off), 1, &insn);
            if (count > 0) {
                assert(count == 1);
                size_t j;
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
                        uintptr_t dest = 0;
                        for (int n = 0; n < detail->groups_count; n++) {
                            dprintf("%s ", cs_group_name(handle, detail->groups[n]));
                            if(detail->groups[n] == cs_group_type::CS_GRP_CALL) {
                                if(i->detail->x86.operands[0].type == X86_OP_IMM) {
                                    // Follow the branch
                                    dest = i->detail->x86.operands[0].imm;
                                    break;
                                } else {
                                    // Dynamic dispatch: for now just ignore it
                                    hit_branch = true;
                                    break;
                                }
                            }
                            if(detail->groups[n] == cs_group_type::CS_GRP_BRANCH_RELATIVE) {
                                dest = i->detail->x86.operands[0].imm;
                                dprintf(" x86_jmp! %x\n", dest);
                                if(strcmp(i->mnemonic, "jmp") == 0) {
                                    // Just follow unconditional branch
                                } else {
                                    // Hook the branch, but don't push successors: we
                                    // will hook them when the branch is hit.
                                    hook_branch(cpu, i->address, i);
                                    hit_branch = true;
                                    break;
                                }
                            }
                        }
                        dprintf("\n");
                        if(hit_branch) { continue; }
                        if(dest == 0) { continue; }
                        if(seen.contains(dest)) { continue; }
                        dprintf("\n\t\t -> %x\n", dest);
                        seen.insert(dest);
                        blocks.push_back(dest);

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

    char* mem = cpu.machine().main_memory().at(0x4134b9, 16);
    for(int i = 0; i < 16; i++) {
        dprintf("%02x ", (unsigned char)mem[i]);
    }
    dprintf("\n");

    cs_close(&handle);
}



static uint64_t install_coverage_hooks(tinykvm::Machine& machine) {
    uint64_t start_address = machine.registers().rip;
    dprintf("elf start @ %p\n", start_address);
    char *entry_mem = machine.main_memory().at(start_address, sizeof(uint32_t));
    ////*((uint8_t*)entry_mem + 0) = 0x90;
    //*((uint8_t*)entry_mem + 1) = 0x90;
    //*((uint8_t*)entry_mem + 2) = 0x90;
    dprintf("bytes at start: %s\n", entry_mem);
    hook_block(machine.cpu(), start_address);

    print_gdt_entries(machine.main_memory().at(machine.get_special_registers().gdt.base), 7);
    machine.print_exception_handlers();

    machine.install_output_handler([](tinykvm::vCPU& cpu, unsigned int io_port, unsigned int val) {
        if(io_port != 0x20) { return; }
        dprintf("custom io handler, val=%llx\n", val);
        uint32_t pc = val - 1; // INT3 advances by one byte
        auto host_code = (uint32_t*)cpu.machine().main_memory().at(pc, 0x10);
        auto host_stack = (uint64_t*)cpu.machine().main_memory().at(cpu.registers().rsp, 0x30);
        uint64_t rflags = host_stack[3];

        // Load correct trampoline page based off of index
        uint32_t index = *(uint8_t*)(((char*)host_code) + 1);
        uintptr_t inst_disp = pc % 0x1000;
        auto page = trampoline.at(index);
        assert(page.present.contains(inst_disp));

        dprintf("trampoline h:%x contains\n", page.host_addr);

        host_code = (uint32_t*)(page.host_addr + inst_disp);
        dprintf("inst=%x\n", *host_code);
        csh handle;
        cs_insn *insn;
        size_t count;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
            return;
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        count = cs_disasm(handle,
                (const uint8_t*)(page.host_addr + inst_disp),
                0x10,
                pc,
                1,
                &insn);
        assert(count == 1);
        // By default, we fallthrough the branch.
        uint64_t target = pc + 2;

        auto evaluate_condition = [&](const char* mnemonic) -> bool {
            bool cf = (rflags & X86_EFLAGS_CF) != 0;
            bool zf = (rflags & X86_EFLAGS_ZF) != 0;
            bool sf = (rflags & X86_EFLAGS_SF) != 0;
            bool of = (rflags & X86_EFLAGS_OF) != 0;
            if (strcmp(mnemonic, "je") == 0 || strcmp(mnemonic, "jz") == 0) {
                return zf;
            } else if (strcmp(mnemonic, "jne") == 0 || strcmp(mnemonic, "jnz") == 0) {
                return !zf;
            } else if (strcmp(mnemonic, "ja") == 0 || strcmp(mnemonic, "jnbe") == 0) {
                return !cf && !zf;
            } else if (strcmp(mnemonic, "jae") == 0 || strcmp(mnemonic, "jnb") == 0 || strcmp(mnemonic, "jnc") == 0) {
                return !cf;
            } else if (strcmp(mnemonic, "jb") == 0 || strcmp(mnemonic, "jnae") == 0 || strcmp(mnemonic, "jc") == 0) {
                return cf;
            } else if (strcmp(mnemonic, "jbe") == 0 || strcmp(mnemonic, "jna") == 0) {
                return cf || zf;
            } else if (strcmp(mnemonic, "jg") == 0 || strcmp(mnemonic, "jnle") == 0) {
                return !zf && (sf == of);
            } else if (strcmp(mnemonic, "jge") == 0 || strcmp(mnemonic, "jnl") == 0) {
                return sf == of;
            } else if (strcmp(mnemonic, "jl") == 0 || strcmp(mnemonic, "jnge") == 0) {
                return sf != of;
            } else if (strcmp(mnemonic, "jle") == 0 || strcmp(mnemonic, "jng") == 0) {
                return zf || (sf != of);
            } else {
                assert(false);
                return false; // Unknown
            }
        };
        bool should_jump = evaluate_condition(insn->mnemonic);
        if (should_jump) {
            target = insn->detail->x86.operands[0].imm;
            dprintf("hit %s -> taking branch to %llx\n", insn->mnemonic, target);
        } else {
            dprintf("hit %s -> not taking branch, fallthrough to %llx\n", insn->mnemonic, target);
        }
        printf("%x -> %x\n", pc, target);
        cpu.registers().rax = target;
        cpu.set_registers(cpu.registers());
        cs_close(&handle);

        hook_block(cpu, target);

        return;
    });


    //*(uint8_t*)entry_mem = 0xF1;
    return 0;
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
        .relocate_fixed_mmap = (getenv("GO") == nullptr),
        .executable_heap = dyn_elf.is_dynamic,
    };
    tinykvm::Machine master_vm {binary, options};

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
        master_vm.fds().set_open_readable_callback(
            [&] (std::string& path) -> bool {
            if(getenv("ALL_PATHS")) { return true; }
                return std::find(allowed_readable_paths.begin(),
                    allowed_readable_paths.end(), path) != allowed_readable_paths.end();
            }
        );
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
