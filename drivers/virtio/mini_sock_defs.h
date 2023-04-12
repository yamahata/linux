/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * mini sock definitions
 *
 * Copyright (c) 2023 Intel Corporation
 *
 * Author:
 *  Isaku Yamahata <isaku.yamahata@gmail.com>
 */
#ifndef _DRIVERS_MINI_SOCK_H
#define _DRIVERS_MINI_SOCK_H

/*
 * Duplicate virtio definitions to avoid accidental use of undesired
 * definitions.
 */

/* Magic value ("virm" string) - Read Only */
#define MINI_SOCK_MMIO_MAGIC_VALUE	0x000

/* mini sock device version - Read Only */
#define MINI_SOCK_MMIO_VERSION		0x004

/* mini sock device ID - Read Only */
#define MINI_SOCK_MMIO_DEVICE_ID	0x008

/* min sock vendor ID - Read Only */
#define MINI_SOCK_MMIO_VENDOR_ID	0x00c

/* Selected queue's Descriptor Table address, 64 bits in two halves */
#define MINI_SOCK_MMIO_QUEUE_DESC_LOW	0x080
#define MINI_SOCK_MMIO_QUEUE_DESC_HIGH	0x084

#define MINI_SOCK_MMIO_SIZE		0x100

#define MINI_SOCK_MAGIC			0x6D726976	/* 'virm' != VIRT_MAGIC */
#define MINI_SOCK_VERSION		1
#define MINI_SOCK_VENDOR		0x554D4551	/* 'QEMU' */
#define MINI_SOCK_ID			19 /* virtio vsock transport */

#endif /* _DRIVERS_MINI_SOCK_H */
