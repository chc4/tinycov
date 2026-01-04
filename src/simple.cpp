#include <tinykvm/machine.hpp>
#include <tinykvm/common.hpp>
#include <linux/kvm.h>
#include <tinykvm/amd64/gdt.hpp>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include "assert.hpp"
#include "load_file.hpp"

#include <capstone/capstone.h>

#include <tinykvm/rsp_client.hpp>
#define GUEST_MEMORY   0x80000000  /* 2GB memory */
#define GUEST_WORK_MEM 1024UL * 1024*1024 /* MB working mem */

static uint64_t verify_exists(tinykvm::Machine& vm, const char* name)
{
	uint64_t addr = vm.address_of(name);
	if (addr == 0x0) {
//		fprintf(stderr, "Error: '%s' is missing\n", name);
//		exit(1);
	}
	return addr;
}

inline timespec time_now();
inline long nanodiff(timespec start_time, timespec end_time);

static uint32_t install_coverage_hooks(tinykvm::Machine& machine) {
    uint32_t start_address = machine.registers().rip;
    printf("elf start @ %p\n", start_address);
    char *entry_mem = machine.main_memory().at(start_address, sizeof(uint32_t));
    *((uint8_t*)entry_mem + 0) = 0xCC;
    //*((uint8_t*)entry_mem + 0) = 0x90;
    *((uint8_t*)entry_mem + 1) = 0x90;
    *((uint8_t*)entry_mem + 2) = 0x90;
    printf("bytes at start: %s\n", entry_mem);

    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); //
    size_t off = 0;
    while(true) {
        bool hit_branch = false;
        // disassemble one inst at a time until we hit the end of the basic block
        count = cs_disasm(handle, (const uint8_t*)(entry_mem + off), 0x1000, (uint32_t)(uintptr_t)(start_address + off), 1, &insn);
        if (count > 0) {
            size_t j;
            for (j = 0; j < count; j++) {
                cs_insn *i = &(insn[j]);
                printf("0x%"PRIx64":\t%s\t\t%s\n", i->address, i->mnemonic,
                        i->op_str);
                cs_detail *detail = i->detail;
                if (detail->groups_count > 0) {
                    printf("\tinstruction group: ");
                    for (int n = 0; n < detail->groups_count; n++) {
                        printf("%s ", cs_group_name(handle, detail->groups[n]));
                        if(detail->groups[n] == x86_insn_group::X86_GRP_JUMP) {
                            printf(" x86_jmp!");
                            //*(uint8_t*)(entry_mem + off) = 0xCD;
                            //*(uint8_t*)(entry_mem + off + 1) = 0x03;
                            //*(uint8_t*)(entry_mem + off) = 0xCC;
                            hit_branch = true;
                        }
                    }
                    printf("\n");
                }
                off += i->size;
            }

            cs_free(insn, count);
        } else {
            printf("ERROR: Failed to disassemble given code! final off: %llx (%lld)\n", off, off);
            break;
        }
        if(hit_branch){
            break;
        }
    }

    cs_close(&handle);

    print_gdt_entries(machine.main_memory().at(machine.get_special_registers().gdt.base), 7);
    machine.print_exception_handlers();

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

    install_coverage_hooks(master_vm);

	master_vm.install_output_handler([](tinykvm::vCPU& cpu, unsigned int io_port, unsigned int val) {
        printf("got custom output %x %x\n", io_port, val);
        return;
    });
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
