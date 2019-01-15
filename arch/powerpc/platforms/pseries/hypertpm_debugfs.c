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

#define HYPERTPM_BUFSIZE 4096

struct hypertpm {
	unsigned long handle;
	struct mutex buffer_mutex;
	size_t response_length;
	bool response_read;
	u8 data_buffer[HYPERTPM_BUFSIZE];
};

ssize_t hypertpm_read(struct file *file, char __user *buf,
		      size_t size, loff_t *off)
{
	struct hypertpm *htpm = file->private_data;
	ssize_t ret_size = 0;
	int rc;

	mutex_lock(&htpm->buffer_mutex);

	if (htpm->response_length) {
		htpm->response_read = true;

		ret_size = min_t(ssize_t, size, htpm->response_length);
		if (!ret_size) {
			htpm->response_length = 0;
			goto out;
		}

		rc = copy_to_user(buf, htpm->data_buffer + *off, ret_size);
		if (rc) {
			memset(htpm->data_buffer, 0, HYPERTPM_BUFSIZE);
			htpm->response_length = 0;
			ret_size = -EFAULT;
		} else {
			memset(htpm->data_buffer + *off, 0, ret_size);
			htpm->response_length -= ret_size;
			*off += ret_size;
		}
	}

out:
	if (!htpm->response_length) {
		*off = 0;
	}
	mutex_unlock(&htpm->buffer_mutex);
	return ret_size;
}

ssize_t hypertpm_write(struct file *file, const char __user *buf,
		       size_t size, loff_t *off)
{
	struct hypertpm *htpm = file->private_data;
	int ret = 0;
	unsigned long retbuf[PLPAR_HCALL_BUFSIZE];
	ssize_t ret_size;

	if (size > HYPERTPM_BUFSIZE)
		return -E2BIG;

	mutex_lock(&htpm->buffer_mutex);

	/* Cannot perform a write until the read has cleared either via
	 * tpm_read or a user_read_timer timeout. This also prevents split
	 * buffered writes from blocking here.
	 */
	if (!htpm->response_read && htpm->response_length) {
		ret = -EBUSY;
		goto out;
	}

	if (copy_from_user(htpm->data_buffer, buf, size)) {
		ret = -EFAULT;
		goto out;
	}

	if (size < 6 ||
	    size < be32_to_cpu(*((__be32 *)(htpm->data_buffer + 2)))) {
		ret = -EINVAL;
		goto out;
	}

	htpm->response_length = 0;
	htpm->response_read = false;
	*off = 0;

	/* TODO: using a dummy handle for now */
	/* issue the hcall and store result back into same buffer */
	ret = plpar_hcall(H_TPM_COMM, retbuf, 0, size, htpm->data_buffer,
			  HYPERTPM_BUFSIZE, htpm->data_buffer);

        ret_size = retbuf[0];

	if (ret == H_SUCCESS) {
		htpm->response_length = retbuf[0];
		ret = size;
	}
out:
	mutex_unlock(&htpm->buffer_mutex);
	return ret;
}

static int hypertpm_open(struct inode *inode, struct file *file)
{
	struct hypertpm *htpm;

	htpm = kzalloc(sizeof(*htpm), GFP_KERNEL);
	if (htpm == NULL)
		return -ENOMEM;

	file->private_data = htpm;
	mutex_init(&htpm->buffer_mutex);

	/* TODO: open handle hcall */

	return 0;
}

static int hypertpm_release(struct inode *inode, struct file *file)
{
	struct hypertpm *htpm = file->private_data;

	/* TODO: close handle hcall */

	file->private_data = NULL;
	htpm->response_length = 0;
	htpm->handle = 0;
	kfree(htpm);

	return 0;
}

static const struct file_operations hypertpm_fops = {
	.llseek = no_llseek,
	.open = hypertpm_open,
	.read = hypertpm_read,
	.write = hypertpm_write,
	.release = hypertpm_release,
};

static int __init hypertpm_init(void)
{
	struct dentry *htpm_file;

	if (!firmware_has_feature(FW_FEATURE_LPAR))
		return 0;

	htpm_file = debugfs_create_file("hypertpm", 0600,
					 NULL,
					 NULL,
					 &hypertpm_fops);
	if (!htpm_file)
		return -ENOMEM;

	return 0;
}
machine_device_initcall(pseries, hypertpm_init);
