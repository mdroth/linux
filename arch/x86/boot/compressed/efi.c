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

/* Get vendor table address/guid from EFI config table at the given index */
static int get_vendor_table(void *cfg_tbl, unsigned int idx,
			    unsigned long *vendor_tbl_pa,
			    efi_guid_t *vendor_tbl_guid,
			    bool efi_64)
{
	if (efi_64) {
		efi_config_table_64_t *tbl_entry =
			(efi_config_table_64_t *)cfg_tbl + idx;

		if (!IS_ENABLED(CONFIG_X86_64) && tbl_entry->table >> 32) {
			debug_putstr("Error: EFI config table entry located above 4GB.\n");
			return -EINVAL;
		}

		*vendor_tbl_pa		= tbl_entry->table;
		*vendor_tbl_guid	= tbl_entry->guid;

	} else {
		efi_config_table_32_t *tbl_entry =
			(efi_config_table_32_t *)cfg_tbl + idx;

		*vendor_tbl_pa		= tbl_entry->table;
		*vendor_tbl_guid	= tbl_entry->guid;
	}

	return 0;
}

/**
 * Given EFI config table, search it for the physical address of the vendor
 * table associated with GUID.
 *
 * @cfg_tbl_pa:        pointer to EFI configuration table
 * @cfg_tbl_len:       number of entries in EFI configuration table
 * @guid:              GUID of vendor table
 * @efi_64:            true if using 64-bit EFI
 * @vendor_tbl_pa:     location to store physical address of vendor table
 *
 * Returns 0 on success. On error, return params are left unchanged.
 */
int efi_find_vendor_table(unsigned long cfg_tbl_pa, unsigned int cfg_tbl_len,
			  efi_guid_t guid, bool efi_64, unsigned long *vendor_tbl_pa)
{
	unsigned int i;

	for (i = 0; i < cfg_tbl_len; i++) {
		unsigned long vendor_tbl_pa_tmp;
		efi_guid_t vendor_tbl_guid;
		int ret;

		if (get_vendor_table((void *)cfg_tbl_pa, i,
				     &vendor_tbl_pa_tmp,
				     &vendor_tbl_guid, efi_64))
			return -EINVAL;

		if (!efi_guidcmp(guid, vendor_tbl_guid)) {
			*vendor_tbl_pa = vendor_tbl_pa_tmp;
			return 0;
		}
	}

	return -ENOENT;
}
