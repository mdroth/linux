// SPDX-License-Identifier: GPL-2.0
/*
 * Helpers for early access to EFI configuration table
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Michael Roth <michael.roth@amd.com>
 */

#include "misc.h"
#include <linux/efi.h>
#include <asm/efi.h>

/**
 * Given boot_params, retrieve the physical address of EFI system table.
 *
 * @boot_params:        pointer to boot_params
 * @sys_tbl_pa:         location to store physical address of system table
 * @is_efi_64:          location to store whether using 64-bit EFI or not
 *
 * Returns 0 on success. On error, return params are left unchanged.
 */
int efi_get_system_table(struct boot_params *boot_params, unsigned long *sys_tbl_pa,
			 bool *is_efi_64)
{
	unsigned long sys_tbl;
	struct efi_info *ei;
	bool efi_64;
	char *sig;

	if (!sys_tbl_pa || !is_efi_64)
		return -EINVAL;

	ei = &boot_params->efi_info;
	sig = (char *)&ei->efi_loader_signature;

	if (!strncmp(sig, EFI64_LOADER_SIGNATURE, 4)) {
		efi_64 = true;
	} else if (!strncmp(sig, EFI32_LOADER_SIGNATURE, 4)) {
		efi_64 = false;
	} else {
		debug_putstr("Wrong EFI loader signature.\n");
		return -ENOENT;
	}

	/* Get systab from boot params. */
#ifdef CONFIG_X86_64
	sys_tbl = ei->efi_systab | ((__u64)ei->efi_systab_hi << 32);
#else
	if (ei->efi_systab_hi || ei->efi_memmap_hi) {
		debug_putstr("Error: EFI system table located above 4GB.\n");
		return -EINVAL;
	}
	sys_tbl = ei->efi_systab;
#endif
	if (!sys_tbl) {
		debug_putstr("EFI system table not found.");
		return -ENOENT;
	}

	*sys_tbl_pa = sys_tbl;
	*is_efi_64 = efi_64;
	return 0;
}

/**
 * Given boot_params, locate EFI system table from it and return the physical
 * address EFI configuration table.
 *
 * @boot_params:        pointer to boot_params
 * @cfg_tbl_pa:         location to store physical address of config table
 * @cfg_tbl_len:        location to store number of config table entries
 * @is_efi_64:          location to store whether using 64-bit EFI or not
 *
 * Returns 0 on success. On error, return params are left unchanged.
 */
int efi_get_conf_table(struct boot_params *boot_params, unsigned long *cfg_tbl_pa,
		       unsigned int *cfg_tbl_len, bool *is_efi_64)
{
	unsigned long sys_tbl_pa = 0;
	int ret;

	if (!cfg_tbl_pa || !cfg_tbl_len || !is_efi_64)
		return -EINVAL;

	ret = efi_get_system_table(boot_params, &sys_tbl_pa, is_efi_64);
	if (ret)
		return ret;

	/* Handle EFI bitness properly */
	if (*is_efi_64) {
		efi_system_table_64_t *stbl =
			(efi_system_table_64_t *)sys_tbl_pa;

		*cfg_tbl_pa	= stbl->tables;
		*cfg_tbl_len	= stbl->nr_tables;
	} else {
		efi_system_table_32_t *stbl =
			(efi_system_table_32_t *)sys_tbl_pa;

		*cfg_tbl_pa	= stbl->tables;
		*cfg_tbl_len	= stbl->nr_tables;
	}

	return 0;
}
