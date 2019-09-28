// SPDX-License-Identifier: GPL-2.0
/*
 * AMD IOMMU driver
 *
 * Copyright (C) 2018 Advanced Micro Devices, Inc.
 *
 * Author: Gary R Hook <gary.hook@amd.com>
 */

#include <linux/debugfs.h>
#include <linux/pci.h>

#include "amd_iommu.h"

static struct dentry *amd_iommu_debugfs;
static DEFINE_MUTEX(amd_iommu_debugfs_lock);

#define	MAX_NAME_LEN	20

extern struct protection_domain *get_domain(struct device *dev);
extern struct protection_domain *to_pdomain(struct iommu_domain *dom);

static ssize_t iova_trans_write(struct file *filp,
				const char __user *buffer,
				size_t count, loff_t *ppos)
{
	struct amd_iommu *iommu = filp->private_data;
	struct amd_iommu_debug *dbg = &iommu->dbg;
	unsigned long iova, spa = 0;
	struct iommu_domain *domain;
	struct pci_dev *pdev;
	char workarea[64];
	ssize_t len;
	int ret;
	void *kaddr;
	unsigned long pfn, offset;

	if (*ppos != 0)
		return -EINVAL;

	if (count >= sizeof(workarea))
		return -ENOSPC;

	len = simple_write_to_buffer(workarea, sizeof(workarea) - 1, ppos,
				     buffer, count);
	if (len < 0)
		return len;

	workarea[len] = '\0';
	ret = kstrtoul(workarea, 16, &iova);
	if (ret)
		return -EIO;

	pdev = pci_get_domain_bus_and_slot(0, PCI_BUS_NUM(dbg->devid),
					dbg->devid & 0xff);
	if (!pdev)
		return -EINVAL;

	domain = iommu_get_domain_for_dev(&pdev->dev);
	if (!domain)
		return -EINVAL;

	spa = iommu_iova_to_phys(domain, iova);
	if (spa == 0) {
		pr_err("Failed to get spa for iova 0x%lx\n", iova);
		return -EINVAL;
	}
 
	pr_info("Found iova 0x%lx phys 0x%lx\n", iova, spa);
	pfn = spa >> PAGE_SHIFT;
	offset = spa & ~PAGE_MASK;

	kaddr = memremap(pfn << PAGE_SHIFT, PAGE_SIZE, MEMREMAP_WB);
	if (!kaddr) {
		pci_err(pdev, "failed to map pfn 0x%lx\n", pfn);
		return -EINVAL;
	}
	print_hex_dump(KERN_DEBUG, "AMD-Vi: ", DUMP_PREFIX_OFFSET,
			32, 8, kaddr + offset, 128, false);
	memunmap(kaddr);

	return len;
}

static ssize_t mapping_trace_write(struct file *filp,
				const char __user *buffer,
				size_t count, loff_t *ppos)
{
	struct amd_iommu *iommu = filp->private_data;
	struct amd_iommu_debug *dbg = &iommu->dbg;
	char workarea[64];
	ssize_t len;
	unsigned long val;
	int ret;

	if (*ppos != 0)
		return -EINVAL;

	if (count >= sizeof(workarea))
		return -ENOSPC;

	len = simple_write_to_buffer(workarea, sizeof(workarea) - 1, ppos,
				     buffer, count);
	if (len < 0)
		return len;

	workarea[len] = '\0';
	ret = kstrtoul(workarea, 10, &val);
	if (ret)
		return -EIO;

	if (dbg->devid == PCI_ANY_ID) {
		pr_err("Invalide device id %u\n", dbg->devid);
		return -EINVAL;
	}

	dbg->mapping_trace_enabled = val;
	printk("DEBUG: %s: %s debug for devid=%#x, domid=%#x\n", __func__,
		val? "Enabled" : "Disabled", dbg->devid, dbg->domid);

	return len;
}

static ssize_t mapping_trace_read(struct file *filp,
				char __user *buf,
				size_t len, loff_t *ppos)
{
	struct amd_iommu *iommu = filp->private_data;
	struct amd_iommu_debug *dbg = &iommu->dbg;
	size_t size;
	ssize_t ret;
	char workarea[64];

	size = scnprintf(workarea, 64, "%u", dbg->mapping_trace_enabled);

	ret = simple_read_from_buffer(buf, len, ppos, workarea, size);
	return ret;
}

static ssize_t intremap_trace_write(struct file *filp,
				const char __user *buffer,
				size_t count, loff_t *ppos)
{
	struct amd_iommu *iommu = filp->private_data;
	struct amd_iommu_debug *dbg = &iommu->dbg;
	char workarea[64];
	ssize_t len;
	unsigned long val;
	int ret;

	if (*ppos != 0)
		return -EINVAL;

	if (count >= sizeof(workarea))
		return -ENOSPC;

	len = simple_write_to_buffer(workarea, sizeof(workarea) - 1, ppos,
				     buffer, count);
	if (len < 0)
		return len;

	workarea[len] = '\0';
	ret = kstrtoul(workarea, 10, &val);
	if (ret)
		return -EIO;

	if (dbg->devid == PCI_ANY_ID) {
		pr_err("Invalide device id %u\n", dbg->devid);
		return -EINVAL;
	}

	dbg->intremap_trace_enabled = val;
	printk("DEBUG: %s: %s debug for devid=%#x, domid=%#x\n", __func__,
		val? "Enabled" : "Disabled", dbg->devid, dbg->domid);

	return len;
}

static ssize_t intremap_trace_read(struct file *filp,
				char __user *buf,
				size_t len, loff_t *ppos)
{
	struct amd_iommu *iommu = filp->private_data;
	struct amd_iommu_debug *dbg = &iommu->dbg;
	size_t size;
	ssize_t ret;
	char workarea[64];

	size = scnprintf(workarea, 64, "%u", dbg->intremap_trace_enabled);

	ret = simple_read_from_buffer(buf, len, ppos, workarea, size);
	return ret;
}

static ssize_t devid_write(struct file *filp,
				const char __user *buffer,
				size_t count, loff_t *ppos)
{
	struct iommu_domain *domain;
	struct protection_domain *pdomain;
	struct amd_iommu *iommu = filp->private_data;
	struct amd_iommu_debug *dbg = &iommu->dbg;
	struct pci_dev *pdev;
	char workarea[64];
	ssize_t len;
	unsigned long val;
	int ret;

	if (*ppos != 0)
		return -EINVAL;

	if (count >= sizeof(workarea))
		return -ENOSPC;

	len = simple_write_to_buffer(workarea, sizeof(workarea) - 1, ppos,
				     buffer, count);
	if (len < 0)
		return len;

	workarea[len] = '\0';
	ret = kstrtoul(workarea, 16, &val);
	if (ret)
		return -EIO;

	dbg->devid = val;

	pdev = pci_get_domain_bus_and_slot(0, PCI_BUS_NUM(dbg->devid),
					dbg->devid & 0xff);
	domain = iommu_get_domain_for_dev(&pdev->dev);
	pdomain = to_pdomain(domain);
	dbg->domid = pdomain->id;
	pdomain->dbg = dbg;

	return len;
}

static ssize_t devid_read(struct file *filp,
				char __user *buf,
				size_t len, loff_t *ppos)
{
	struct amd_iommu *iommu = filp->private_data;
	struct amd_iommu_debug *dbg = &iommu->dbg;
	size_t size;
	ssize_t ret;
	char workarea[64];

	size = scnprintf(workarea, 64, "%#x", dbg->devid);

	ret = simple_read_from_buffer(buf, len, ppos, workarea, size);
	return ret;
}

static const struct file_operations mapping_trace_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = mapping_trace_write,
	.read = mapping_trace_read,
};

static const struct file_operations intremap_trace_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = intremap_trace_write,
	.read = intremap_trace_read,
};

static const struct file_operations devid_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = devid_write,
	.read = devid_read,
};

#if 0
static const struct file_operations disable_dom_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = disable_dom_write,
};
#endif

static const struct file_operations iova_trans_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = iova_trans_write,
};

void amd_iommu_debugfs_setup(struct amd_iommu *iommu)
{
	char name[MAX_NAME_LEN + 1];
	struct dentry *fp, *debugfs;
	struct amd_iommu_debug *dbg = &iommu->dbg;

	mutex_lock(&amd_iommu_debugfs_lock);

	if (!amd_iommu_debugfs)
		amd_iommu_debugfs = debugfs_create_dir("amd",
						       iommu_debugfs_dir);
	snprintf(name, MAX_NAME_LEN, "iommu%02d", iommu->index);
	debugfs = debugfs_create_dir(name, amd_iommu_debugfs);
	if (!debugfs)
		pr_err("Failed to create amd iommu debugfs.\n");

	fp = debugfs_create_file("iova_trans", 0600, debugfs, iommu,
				&iova_trans_fops);
	if (!fp)
		pr_err("Failed to create iova_trans files.\n");

	dbg->devid = PCI_ANY_ID;
	fp = debugfs_create_file("devid", 0600, debugfs, iommu,
				&devid_fops);
	if (!fp)
		pr_err("Failed to create devid files.\n");

#if 0
	fp = debugfs_create_file("disable_domain", 0600, debugfs,
						iommu, &disable_dom_fops);
	if (!fp)
		pr_err("Failed to create disable_domain files.\n");
#endif
	fp = debugfs_create_file("mapping_trace_enable", 0600, debugfs, iommu,
				&mapping_trace_fops);
	if (!fp)
		pr_err("Failed to create mapping_trace_enable files.\n");

	fp = debugfs_create_file("intremap_trace_enable", 0600, debugfs, iommu,
				&intremap_trace_fops);
	if (!fp)
		pr_err("Failed to create intremap_trace_enable files.\n");

	mutex_unlock(&amd_iommu_debugfs_lock);
}
