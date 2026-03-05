cmake_minimum_required(VERSION 3.15)

# Guest must be built for amd64 bare metal, so force the toolchain
set(CMAKE_ASM_NASM_OBJECT_FORMAT elf64)

find_program(NASM nasm REQUIRED)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/interrupts_asm.o
    COMMAND ${NASM} -f elf64
            -o ${CMAKE_CURRENT_BINARY_DIR}/interrupts_asm.o
            ${CMAKE_CURRENT_SOURCE_DIR}/interrupts.asm
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/interrupts.asm
            ${CMAKE_CURRENT_SOURCE_DIR}/guest.h
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/guest.o
    COMMAND ${CMAKE_CXX_COMPILER} -O3 -c -mno-mmx -mno-sse -mno-sse2 -mno-sse3 -mno-3dnow -mno-red-zone -mno-80387 -fno-pie -fno-stack-protector -ffreestanding -masm=intel
            -o ${CMAKE_CURRENT_BINARY_DIR}/guest.o
            ${CMAKE_CURRENT_SOURCE_DIR}/guest.cpp
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/guest.cpp
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/interrupts.bin
    COMMAND ld -T ${CMAKE_CURRENT_SOURCE_DIR}/guest.ld
            --oformat binary
            --allow-multiple-definition
            -o ${CMAKE_CURRENT_BINARY_DIR}/interrupts.bin
            ${CMAKE_CURRENT_BINARY_DIR}/interrupts_asm.o
            ${CMAKE_CURRENT_BINARY_DIR}/guest.o
    DEPENDS
            ${CMAKE_CURRENT_BINARY_DIR}/interrupts_asm.o
            ${CMAKE_CURRENT_BINARY_DIR}/guest.o
            ${CMAKE_CURRENT_SOURCE_DIR}/guest.ld
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/interrupts_wrapped.o
    COMMAND ld -r -b binary -m elf_x86_64
            -o ${CMAKE_CURRENT_BINARY_DIR}/interrupts_wrapped.o
            interrupts.bin
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/interrupts.bin
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# For debugging
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/interrupts.o
    COMMAND ld -r -b binary
            -o ${CMAKE_CURRENT_BINARY_DIR}/interrupts.o
            interrupts.bin
    COMMAND objcopy --set-section-alignment .data=16
            ${CMAKE_CURRENT_BINARY_DIR}/interrupts.o
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/interrupts.bin
    COMMENT "Wrapping kernel.bin as linkable object"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

#add_custom_command(
#    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/interrupts.bin
#    COMMAND ${NASM} -f bin -o ${CMAKE_CURRENT_BINARY_DIR}/interrupts.bin
#            ${CMAKE_CURRENT_SOURCE_DIR}/interrupts.asm
#    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/interrupts.asm
#    COMMENT "Assembling guest kernel flat binary"
#)

add_custom_target(guest_interrupts_obj ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/interrupts_wrapped.o
)

add_dependencies(tinykvm guest_interrupts_obj)
target_link_libraries(tinykvm PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/interrupts_wrapped.o)
