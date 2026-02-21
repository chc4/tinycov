SECTIONS {
    . = 0x0;
    .text : {
        interrupts_asm.o(.text)   /* asm must come first */
        *(.text)
    }
    .data : { *(.data) }
    .rodata : { *(.rodata) }
    .bss : { *(.bss) }
}
