
#ifndef __MMIO_DRV_H__
#define __MMIO_DRV_H__

#include <linux/types.h>

struct mmio_drv_params {
	__u64 mmio_address;
	__u64 mmio_length;
	__u64 mmio_iosize;
	__u64 mmio_stride;
};

#define MMIO_DRV_SET_PARAMS	_IOW('S', 0x01, struct mmio_drv_params)

#ifdef __KERNEL__
#endif

#endif
