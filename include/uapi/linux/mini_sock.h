/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_MINI_SOCK_H
#define _UAPI_MINI_SOCK_H

#include <linux/types.h>

#define MINI_SOCK_CID_ANY		((__u64)-1)
#define MINI_SOCK_CID_HYPERVISOR	((__u64)1)
#define MINI_SOCK_CID_HOST		((__u64)2)

#define MINI_SOCK_PORT_ANY		((__u32)-1)

#define MINI_SOCK_SUCCESS		((__s32)0)
#define MINI_SOCK_SUCCESS_DONE		((__s32)1)
/* or -error for MINI_SOCK_STATE_ERROR */

#define MINI_SOCK_STATE_SUCCESS		((__s32)0)
#define MINI_SOCK_STATE_ERROR		((__s32)-1)
#define MINI_SOCK_STATE_ONREQUEST	((__s32)-2)
#define MINI_SOCK_STATE_INFLIGHT	((__s32)-3)

struct mini_sock_state {
	__le32 ret;
	__le32 state;
} __attribute__((packed));

struct mini_sock_hdr {
	__le64 src_cid;
	__le64 dst_cid;
	__le32 src_port;
	__le32 dst_port;
	__le32 len;			/* payload length without this header. */
	__le16 type;			/* enum mini_sock_type */
	__le16 op;			/* enum mini_sock_op */
	__le32 flags;
	union {
		struct {
			union {
				__le32 buf_alloc;	/* vsock name */
				__le32 ret;		/* repurpose for mini-sock */
			};
			union {
				__le32 fwd_cnt;		/* vsock name */
				__le32 state;		/* repurpose for mini-sock */
			};
		};
		struct mini_sock_state _state;
	};
} __attribute__((packed));

/* To explicitly show that this data includes payload. */
struct mini_sock_hdr_pyld {
	struct mini_sock_hdr hdr;
	__u8 payload[];
} __attribute__((packed));

enum mini_sock_type {
	MINI_SOCK_TYPE_STREAM = 1,
	MINI_SOCK_TYPE_DGRAM = 3,
};

enum mini_sock_op {
	MINI_SOCK_OP_INVALID = 0,

	MINI_SOCK_OP_REQUEST = 1,

	MINI_SOCK_OP_RESPONSE = 2,

	MINI_SOCK_OP_RST = 3,

	MINI_SOCK_OP_SHUTDOWN = 4,

	/* To send/receive payload */
	MINI_SOCK_OP_RW = 5,

	/* system configuration: new for mini-sock */
	MINI_SOCK_OP_CONFIG = 64,
};

/* MINI_SOCK_OP_RW flags values */
enum mini_sock_rw {
	MINI_SOCK_RW_SEND = 1,
	MINI_SOCK_RW_RECV = 2,
};

/* MINI_SOCK_OP_CONFIG flags value */
enum mini_sock_config_op {
	MINI_SOCK_CONFIG_GET = 1,
	MINI_SOCK_CONFIG_SET = 2,
};

/* MINI_SOCK_OP_CONFIG keys */
#define MINI_SOCK_CONFIG_CID    0ULL    /* __le64 read-only */
#define MINI_SOCK_CONFIG_MTU    1ULL    /* __le64 read-only */
#define MINI_SOCK_CONFIG_MSI    2ULL    /* MSIMessage read-write */

struct mini_sock_config_data {
	__le64 key;
	__u8 data[];
} __attribute__((packed));

#define MINI_SOCK_COMPLETE_ANY	((struct mini_sock_hdr_pyld *)NULL)

#define MINI_SOCK_TYPE	'm'

/* Raw socket-like API to handle packet */
#define MINI_SOCK_POST		_IOWR(MINI_SOCK_TYPE, 0x0, struct mini_sock_hdr_pyld)
#define MINI_SOCK_COMPLETE	_IOWR(MINI_SOCK_TYPE, 0x1, struct mini_sock_hdr_pyld *)

#endif /* _UAPI_MINI_SOCK_H */
