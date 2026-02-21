SECTIONS {
    . = 0x2000;
    .text : {
        interrupts_asm.o(.text)   /* asm must come first */
        *(.text)
    }
    .data : { *(.data) }
    .rodata : { *(.rodata) }
    .bss : { *(.bss) }

    _guest_end = .;
}
