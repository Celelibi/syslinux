/* -----------------------------------------------------------------------
 *   
 *   Copyright 2008-2009 H. Peter Anvin - All Rights Reserved
 *   Copyright 2009 Intel Corporation; author: H. Peter Anvin
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 *   Boston MA 02110-1301, USA; either version 2 of the License, or
 *   (at your option) any later version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

/*
 * Linker script for the SYSLINUX core
 */

OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
	. = 0;
	ImageBase = .;		/* For gnu-efi's crt0 */
	HIDDEN(__module_start = .);
	. = SEGMENT_START("text-segment", 0) + SIZEOF_HEADERS;
	.text : {
		FILL(0x90909090)
		HIDDEN(__text_start = .);
		*(.text)
		*(.text.*)
		HIDDEN(__text_end = .);
	}

	. = ALIGN(16);

	.rodata : {
		HIDDEN(__rodata_start = .);
		*(.rodata)
		*(.rodata.*)
		HIDDEN(__rodata_end = .);
	}

	. = ALIGN(4);

	.ctors : {
		HIDDEN(__ctors_start = .);
		KEEP (*(SORT(.preinit_array*)))
		KEEP (*(SORT(.init_array*)))
		KEEP (*(SORT(.ctors*)))
		HIDDEN(__ctors_end = .);
	}

	.dtors : {
		HIDDEN(__dtors_start = .);
		KEEP (*(SORT(.fini_array*)))
		KEEP (*(SORT(.dtors*)))
		HIDDEN(__dtors_end = .);
	}

	. = ALIGN(4096);
	.rel : {
		*(.rel.got)
		*(.rel.data)
		*(.rel.data.*)
		*(.rel.ctors)
	}

	. = ALIGN(4);

	.gnu.hash : {
		HIDDEN(__gnu_hash_start = .);
		*(.gnu.hash)
		HIDDEN(__gnu_hash_end = .);
	}


	.dynsym : {
		HIDDEN(__dynsym_start = .);
		*(.dynsym)
		HIDDEN(__dynsym_end = .);
	}

	. = ALIGN(4);

	.dynstr : {
		HIDDEN(__dynstr_start = .);
		*(.dynstr)
		HIDDEN(__dynstr_end = .);
	}

	. = ALIGN(4);

	.dynlink : {
		HIDDEN(__dynlink_start = .);
		*(.dynlink)
		HIDDEN(__dynlink_end = .);
	}

	. = ALIGN(4);

	.got : {
		HIDDEN(__got_start = .);
		KEEP (*(.got.plt))
		KEEP (*(.got))
		HIDDEN(__got_end = .);
	}

	. = ALIGN(4);

	.dynamic : {
		HIDDEN(__dynamic_start = .);
		*(.dynamic)
		HIDDEN(__dynamic_end = .);
	}

	. = ALIGN(16);

	.data : {
		HIDDEN(__data_start = .);
		*(.data)
		*(.data.*)
		*(.lowmem)
		HIDDEN(__data_end = .);
	}

	.reloc : {
		*(.reloc)
	}

	.symtab : {
		*(.symtab)
	}

	.strtab : {
		*(.strtab)
	}

	.bss (NOLOAD) : {
		/* the EFI loader doesn't seem to like a .bss section,
		   so we stick it all into .data: */
		HIDDEN(__bss_start = .);
		*(.bss)
		*(.bss.*)
		*(.bss16)
		*(.hugebss)
		*(COMMON)
		HIDDEN(__bss_end = .);
		*(.sbss)
		*(.scommon)
	}
	HIDDEN(__bss_len = ABSOLUTE(__bss_end) - ABSOLUTE(__bss_start));
	HIDDEN(__bss_dwords = (__bss_len + 3) >> 2);

	. = ALIGN(128);

	/* Very large objects which don't need to be zeroed */

	.hugebss : {
		HIDDEN(__hugebss_start = .);
		*(.hugebss)
		*(.hugebss.*)
		HIDDEN(__hugebss_end = .);
	}

	HIDDEN(_end = .);

	/* Stuff we don't need... */
	/DISCARD/ : {
		*(.eh_frame)
		*(.comment)
	}
}
