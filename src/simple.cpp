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
#include <sys/ioctl.h>
#include <set>
#include "assert.hpp"
#include "load_file.hpp"
#include "sys/mman.h"
#include <asm/processor-flags.h>

#include <capstone/capstone.h>
#include <roaring.hh>

#include <tinykvm/rsp_client.hpp>
#include <tinycov/tinycov.hpp>

#define GUEST_MEMORY   0x80000000  /* 2GB memory */
#define GUEST_WORK_MEM 1024UL * 1024*1024 /* MB working mem */
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
        .split_hugepages = true,
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

    std::unique_ptr<tinycov::CoverageMachine> cov;
    if(getenv("COVERAGE")) {
        cov = std::make_unique<tinycov::CoverageMachine>(master_vm);
        cov->install_hooks();
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
        if(cov) {
            cov->report();
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
