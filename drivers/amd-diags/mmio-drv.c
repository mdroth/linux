
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/debugfs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/compat.h>

#include "mmio-drv.h"

MODULE_LICENSE("GPL");

static unsigned int verbose;
module_param(verbose, uint, 0);
MODULE_PARM_DESC(verbose, " 0 - no output, 1 - open/iomap output, 2 - open/iomap and read/write output");

static struct dentry *debugfs_dir;
static u64 mmio_address;
static u64 mmio_length;
static u64 mmio_iosize;
static u64 mmio_stride;

struct mmio_data {
	u64 address;
	u64 length;
	u64 iosize;
	u64 stride;
	void __iomem *mem;
};

static int mmio_get(void *data, u64 *val)
{
	*val = *(u64 *)data;

	return 0;
}

static int mmio_set(void *data, u64 val)
{
	char *setting;

	if (data == &mmio_iosize) {
		switch (val) {
		case 1:
		case 2:
		case 4:
			break;
		default:
			pr_alert("mmio_drv: invalid mmio_iosize [%llu], must be 1, 2 or 4 (bytes)\n",
				 val);
		}
	}

	if (verbose) {
		if (data == &mmio_address)
			setting = "address";
		else if (data == &mmio_length)
			setting = "length";
		else if (data == &mmio_iosize)
			setting = "iosize";
		else if (data == &mmio_stride)
			setting = "stride";
		else
			setting = "unknown";

		pr_alert("mmio_drv: mmio_set %s to 0x%llx\n", setting, val);
	}

	*(u64 *)data = val;

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(mmio_ops, mmio_get, mmio_set, "%llu\n");

static int mmio_drv_setup(struct mmio_data *data)
{
	/* No private data, that's an error */
	if (!data)
		return -EINVAL;

	/* Already mapped, we're done */
	if (data->mem)
		return 0;

	if (verbose)
		pr_alert("mmio_drv: using address=0x%llx length=%llu, iosize=%llu, stride=%llu\n",
			 data->address, data->length, data->iosize,
			 data->stride);

	/* Validate parameters needed for mapping */
	if (!data->address)
		return -EIO;

	if (!data->length)
		return -EIO;

	data->mem = ioremap_nocache(data->address, data->length);
	if (!data->mem)
		return -EIO;

	if (verbose)
		pr_alert("mmio_drv: mmio address=%p\n", data->mem);

	return 0;
}

static ssize_t mmio_drv_read(struct file *f, char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct mmio_data *data = f->private_data;
	void __iomem *mem_pos;
	char __user *buf_pos;
	char *copy_pos;
	u8 u8_val;
	u16 u16_val;
	u32 u32_val;
	int rc;

	rc = mmio_drv_setup(data);
	if (rc)
		return rc;

	if ((*ppos < 0) || (*ppos > data->length))
		return -EIO;

	if (*ppos == data->length)
		return 0;

	buf_pos = buf;
	mem_pos = data->mem + *ppos;
	while ((buf_pos < (buf + count)) &&
	       (mem_pos < (data->mem + data->length))) {
		switch (data->iosize) {
		case 1:
			u8_val = ioread8(mem_pos);
			copy_pos = (char *)&u8_val;
			if (verbose > 1)
				pr_alert("mmio_drv: performed ioread8 of 0x%02hhx from %p\n",
					 u8_val, mem_pos);
			break;
		case 2:
			u16_val = ioread16(mem_pos);
			copy_pos = (char *)&u16_val;
			if (verbose > 1)
				pr_alert("mmio_drv: performed ioread16 of 0x%04hx from %p\n",
					 u16_val, mem_pos);
			break;
		case 4:
			u32_val = ioread32(mem_pos);
			copy_pos = (char *)&u32_val;
			if (verbose > 1)
				pr_alert("mmio_drv: performed ioread8 of 0x%08x from %p\n",
					 u32_val, mem_pos);
			break;
		default:
			return -EIO;
		}

		if (copy_to_user(buf_pos, copy_pos, data->iosize))
			return -EFAULT;

		buf_pos += data->iosize;
		mem_pos += data->stride;

		*ppos += data->stride;
	}

	return count;
}

static ssize_t mmio_drv_write(struct file *f, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct mmio_data *data = f->private_data;
	void __iomem *mem_pos;
	const char __user *buf_pos;
	char *copy_pos;
	u8 u8_val;
	u16 u16_val;
	u32 u32_val;
	int rc;

	rc = mmio_drv_setup(data);
	if (rc)
		return rc;

	if ((*ppos < 0) || (*ppos > data->length))
		return -EIO;

	if (*ppos == data->length)
		return 0;

	buf_pos = buf;
	mem_pos = data->mem + *ppos;
	while ((buf_pos < (buf + count)) &&
	       (mem_pos < (data->mem + data->length))) {
		switch (data->iosize) {
		case 1:
			copy_pos = (char *)&u8_val;
			break;
		case 2:
			copy_pos = (char *)&u16_val;
			break;
		case 4:
			copy_pos = (char *)&u32_val;
			break;
		default:
			return -EIO;
		}

		if (copy_from_user(copy_pos, buf_pos, data->iosize))
			return -EFAULT;

		switch (data->iosize) {
		case 1:
			if (verbose > 1)
				pr_alert("mmio_drv: performing iowrite8 of 0x%02hhx to %p\n",
					 u8_val, mem_pos);
			iowrite8(u8_val, mem_pos);
			break;
		case 2:
			if (verbose > 1)
				pr_alert("mmio_drv: performing iowrite16 of 0x%04hx to %p\n",
					 u16_val, mem_pos);
			iowrite16(u16_val, mem_pos);
			break;
		case 4:
			if (verbose > 1)
				pr_alert("mmio_drv: performing iowrite32 of 0x%08x to %p\n",
					 u32_val, mem_pos);
			iowrite32(u32_val, mem_pos);
			break;
		default:
			return -EIO;
		}

		buf_pos += data->iosize;
		mem_pos += data->stride;

		*ppos += data->stride;
	}

	if (buf_pos < (buf + count))
		return -EIO;

	return count;
}

static loff_t mmio_drv_llseek(struct file *f, loff_t offset, int whence)
{
	struct mmio_data *data = f->private_data;
	int rc;

	rc = mmio_drv_setup(data);
	if (rc)
		return rc;

	if (whence != SEEK_SET)
		return -EINVAL;

	if ((offset < 0) || (offset > data->length))
		return -EIO;

	f->f_pos = offset;
	f->f_version = 0;

	return offset;
}

static long mmio_drv_ioctl(struct file *f, unsigned int ioctl,
			   unsigned long arg)
{
	struct mmio_data *data = f->private_data;
	struct mmio_drv_params params;
	void __user *argp = (void __user *)arg;

	if (!data)
		return -EINVAL;

	switch (ioctl) {
	case MMIO_DRV_SET_PARAMS:
		if (copy_from_user(&params, argp, sizeof(params)))
			return -EFAULT;

		if (data->mem)
			iounmap(data->mem);

		data->address = params.mmio_address;
		data->length = params.mmio_length;
		data->iosize = params.mmio_iosize;
		data->stride = params.mmio_stride;
		data->mem = NULL;

		return mmio_drv_setup(data);

	default:
		return -EINVAL;
	}
}

#ifdef CONFIG_COMPAT
static long mmio_drv_compat_ioctl(struct file *f, unsigned int ioctl,
				  unsigned long arg)
{
	return mmio_drv_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}
#endif

static int mmio_drv_open(struct inode *inode, struct file *f)
{
	struct mmio_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->address = mmio_address;
	data->length = mmio_length;
	data->iosize = mmio_iosize;
	data->stride = mmio_stride;
	data->mem = NULL;

	f->private_data = data;

	return 0;
}

static int mmio_drv_release(struct inode *inode, struct file *f)
{
	struct mmio_data *data = f->private_data;

	if (data) {
		if (data->mem)
			iounmap(data->mem);
		kfree(data);
	}

	f->private_data = NULL;

	return 0;
}

static const struct file_operations mmio_drv_ops = {
	.owner		= THIS_MODULE,
	.open		= mmio_drv_open,
	.release	= mmio_drv_release,
	.read		= mmio_drv_read,
	.write		= mmio_drv_write,
	.llseek		= mmio_drv_llseek,
	.unlocked_ioctl = mmio_drv_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = mmio_drv_compat_ioctl,
#endif
};

static struct miscdevice mmio_drv_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "mmio_drv",
	.fops = &mmio_drv_ops,
};

static int __init mmio_drv_init(void)
{
	int ret;

	debugfs_dir = debugfs_create_dir("mmio_drv", NULL);
	if (IS_ERR(debugfs_dir)) {
		ret = PTR_ERR(debugfs_dir);
		pr_err("mmio_drv: debugfs_create_dir error (%d)\n", ret);
		goto e_err;
	}

	/* Default to ioread32 and striding 4 bytes at a time */
	mmio_iosize = 4;
	mmio_stride = 4;

	debugfs_create_file("address", S_IRUSR | S_IWUSR, debugfs_dir,
			    &mmio_address, &mmio_ops);
	debugfs_create_file("length",  S_IRUSR | S_IWUSR, debugfs_dir,
			    &mmio_length, &mmio_ops);
	debugfs_create_file("iosize",  S_IRUSR | S_IWUSR, debugfs_dir,
			    &mmio_iosize, &mmio_ops);
	debugfs_create_file("stride",  S_IRUSR | S_IWUSR, debugfs_dir,
			    &mmio_stride, &mmio_ops);

	ret = misc_register(&mmio_drv_miscdev);
	if (ret) {
		pr_err("mmio_drv: misc_register error (%d)\n", ret);
		goto e_debugfs;
	}

	if (verbose)
		pr_alert("mmio_drv: loaded\n");

	return 0;

e_debugfs:
	debugfs_remove_recursive(debugfs_dir);

e_err:
	return ret;
}

static void __exit mmio_drv_exit(void)
{
	misc_deregister(&mmio_drv_miscdev);

	debugfs_remove_recursive(debugfs_dir);
}

module_init(mmio_drv_init);
module_exit(mmio_drv_exit);
