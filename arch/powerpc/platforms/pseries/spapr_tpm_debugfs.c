/*
 * Copyright (C) 2019 Michael Roth IBM Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/machdep.h>

#define SPAPR_TPM_BUFSIZE 4096

struct spapr_tpm {
	unsigned long handle;
	struct mutex buffer_mutex;
	size_t response_length;
	bool response_read;
	u8 data_buffer[SPAPR_TPM_BUFSIZE];
};

ssize_t spapr_tpm_read(struct file *file, char __user *buf,
		      size_t size, loff_t *off)
{
	struct spapr_tpm *stpm = file->private_data;
	ssize_t ret_size = 0;
	int rc;

	mutex_lock(&stpm->buffer_mutex);

	if (stpm->response_length) {
		ret_size = min_t(ssize_t, size, stpm->response_length - *off);
		if (!ret_size) {
			stpm->response_length = 0;
			goto out;
		}

		rc = copy_to_user(buf, stpm->data_buffer + *off, ret_size);
		if (rc) {
			memset(stpm->data_buffer, 0, SPAPR_TPM_BUFSIZE);
			stpm->response_length = 0;
			ret_size = -EFAULT;
			goto out;
		}

		*off += ret_size;

		if (*off == stpm->response_length) {
			memset(stpm->data_buffer + *off, 0, ret_size);
			stpm->response_read = true;
			stpm->response_length = 0;
		}
	}

out:
	if (!stpm->response_read && !stpm->response_length) {
		*off = 0;
		stpm->response_read = true;
	}
	mutex_unlock(&stpm->buffer_mutex);
	return ret_size;
}

enum {
	TPM_COMM_OP_EXECUTE = 1,
	TPM_COMM_OP_IDLE = 2,
	TPM_COMM_OP_STATUS = 3,
};

ssize_t spapr_tpm_write(struct file *file, const char __user *buf,
		       size_t size, loff_t *off)
{
	struct spapr_tpm *stpm = file->private_data;
	int ret = 0;
	unsigned long retbuf[PLPAR_HCALL_BUFSIZE];
	ssize_t ret_size;

	if (size > SPAPR_TPM_BUFSIZE)
		return -E2BIG;

	mutex_lock(&stpm->buffer_mutex);

	/* Cannot perform a write until the read has cleared either via
	 * tpm_read or a user_read_timer timeout. This also prevents split
	 * buffered writes from blocking here.
	 */
	if (!stpm->response_read && stpm->response_length) {
		ret = -EBUSY;
		goto out;
	}

	if (copy_from_user(stpm->data_buffer, buf, size)) {
		ret = -EFAULT;
		goto out;
	}

	if (size < 6 ||
	    size < be32_to_cpu(*((__be32 *)(stpm->data_buffer + 2)))) {
		ret = -EINVAL;
		goto out;
	}

	stpm->response_length = 0;
	stpm->response_read = false;
	*off = 0;

	/* TODO: using a dummy handle for now */
	/* issue the hcall and store result back into same buffer */
	ret = plpar_hcall(H_TPM_COMM, retbuf, TPM_COMM_OP_EXECUTE, size,
			  stpm->data_buffer, SPAPR_TPM_BUFSIZE,
			  stpm->data_buffer);

        ret_size = retbuf[0];

	if (ret == H_SUCCESS) {
		stpm->response_length = retbuf[0];
		ret = size;
	} else {
		stpm->response_read = true;
	}
out:
	mutex_unlock(&stpm->buffer_mutex);
	return ret;
}

static int spapr_tpm_open(struct inode *inode, struct file *file)
{
	struct spapr_tpm *stpm;

	stpm = kzalloc(sizeof(*stpm), GFP_KERNEL);
	if (stpm == NULL)
		return -ENOMEM;

	file->private_data = stpm;
	mutex_init(&stpm->buffer_mutex);
	stpm->response_length = 0;
	stpm->response_read = false;

	return 0;
}

static int spapr_tpm_release(struct inode *inode, struct file *file)
{
	struct spapr_tpm *stpm = file->private_data;

	file->private_data = NULL;
	stpm->response_length = 0;
	stpm->handle = 0;
	kfree(stpm);

	return 0;
}

static const struct file_operations spapr_tpm_fops = {
	.llseek = no_llseek,
	.open = spapr_tpm_open,
	.read = spapr_tpm_read,
	.write = spapr_tpm_write,
	.release = spapr_tpm_release,
};

static int __init spapr_tpm_init(void)
{
	struct dentry *stpm_file;

	if (!firmware_has_feature(FW_FEATURE_LPAR))
		return 0;

	stpm_file = debugfs_create_file("spapr_tpm", 0600,
					 NULL,
					 NULL,
					 &spapr_tpm_fops);
	if (!stpm_file)
		return -ENOMEM;

	return 0;
}
machine_device_initcall(pseries, spapr_tpm_init);
