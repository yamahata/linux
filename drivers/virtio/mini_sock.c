/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * mini sock
 *
 * Copyright (c) 2023 Intel Corporation
 *
 * Author:
 *  Isaku Yamahata <isaku.yamahata@gmail.com>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/irq.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/dma-mapping.h>
#include <linux/miscdevice.h>
#include <linux/interrupt.h>
#include <asm/irqdomain.h>
#include <linux/msi.h>
#include <linux/wait.h>

#include <linux/mini_sock.h>

#include "mini_sock_defs.h"

#define MINI_SOCK_MMIO_BASE_DEFAULT     (0xfec00000 - 4 * 1024)
static void __iomem *mini_sock_virt;
static unsigned long mmio_base = MINI_SOCK_MMIO_BASE_DEFAULT;
module_param_named(mmio, mmio_base, ulong, S_IRUGO);

static int mini_sock_irq = -1;
module_param_named(irq, mini_sock_irq, int, S_IRUGO);

#ifdef CONFIG_X86_64
static struct irq_cfg *mini_sock_irq_cfg;
#endif

static u32 mini_sock_readl(unsigned long offset)
{
	return readl(mini_sock_virt + offset);
}

static void mini_sock_mmio_request(void *virt)
{
	u64 phys = __pa(virt);

#ifdef writeq
	writeq(phys, mini_sock_virt + MINI_SOCK_MMIO_QUEUE_DESC_LOW);
#else
	WARN_ON_ONCE(phys != (u32)phys);
	writel((u32)phys, mini_sock_virt + MINI_SOCK_MMIO_QUEUE_DESC_LOW);
#endif
}

static int mini_sock_config(void *virt, u64 key, void *data, size_t size,
			    bool get)
{
	struct mini_sock_hdr_pyld *hdr_pyld;
	struct mini_sock_hdr *hdr;
	struct mini_sock_config_data *config;

	hdr_pyld = (struct mini_sock_hdr_pyld *)virt;
	hdr = &hdr_pyld->hdr;
	config = (struct mini_sock_config_data *)hdr_pyld->payload;

	hdr_pyld->hdr = (struct mini_sock_hdr) {
		.src_cid = cpu_to_le64(MINI_SOCK_CID_ANY),
		.dst_cid = cpu_to_le64(MINI_SOCK_CID_ANY),
		.src_port = cpu_to_le32(MINI_SOCK_PORT_ANY),
		.dst_port = cpu_to_le32(MINI_SOCK_PORT_ANY),
		.len = cpu_to_le32(sizeof(*config) + size),
		.type = cpu_to_le16(MINI_SOCK_TYPE_DGRAM),
		.op = cpu_to_le16(MINI_SOCK_OP_CONFIG),
		.flags = get ?
		cpu_to_le32(MINI_SOCK_CONFIG_GET) :
		cpu_to_le32(MINI_SOCK_CONFIG_SET),
		.ret = cpu_to_le32(MINI_SOCK_SUCCESS),
		.state = cpu_to_le32(MINI_SOCK_STATE_ONREQUEST),
	};
	config->key = cpu_to_le64(key);
	if (!get)
		memcpy(config->data, data, size);

	mini_sock_mmio_request(virt);

	switch (le32_to_cpu(READ_ONCE(hdr->state))) {
	case MINI_SOCK_STATE_SUCCESS:
		WARN_ON_ONCE(le32_to_cpu(READ_ONCE(hdr->ret)) != 0);
		if (get)
			memcpy(data, config->data, size);
		return 0;
	case MINI_SOCK_STATE_ERROR:
		return le32_to_cpu(READ_ONCE(hdr->ret));
	case MINI_SOCK_STATE_ONREQUEST:
	case MINI_SOCK_STATE_INFLIGHT:
	default:
		WARN_ON_ONCE(1);
		return -EIO;
	}
}

static u64 guest_cid __read_mostly;
#define MINI_SOCK_MTU_MAX	((u64)(128 * 1024))
static u64 mini_sock_mtu __read_mostly;

static DEFINE_SPINLOCK(lock);
static HLIST_HEAD(sorted_in_port);	/* sorted in port number. */
static LIST_HEAD(mini_sock_send);	/* global send queue */
static LIST_HEAD(mini_sock_buf);	/* global recv buf queue */
static LIST_HEAD(mini_sock_resp);	/* global resp queue */
#define MINI_SOCK_PORT_MAX		((u32)-2)
static u32 last_port;			/* port number lastly assigned. */

static DEFINE_MUTEX(mutex_lock);
static struct mini_sock_hdr_pyld *mini_sock_hdr_pyld __read_mostly;
static dma_addr_t mini_sock_dma_addr;

static struct miscdevice mini_sock_dev;

#define MINI_SOCK_QUEUE_MAX	32

struct mini_sock_send {
	struct mini_sock *msock;
	struct list_head list;	/* msock->send */
	struct list_head glist;	/* mini_sock_send above */
	bool completed;

	struct mini_sock_hdr_pyld __user *uhdr_pyld;
	struct mini_sock_hdr_pyld *khdr_pyld;
	dma_addr_t dma_addr;
	size_t len;
};

struct mini_sock_recv_buf {
	struct mini_sock *msock;
	struct list_head list;	/* msock->buf */
	struct list_head glist;	/* mini_sock_buf above */
	bool completed;

	struct mini_sock_hdr_pyld __user *uhdr_pyld;
	struct mini_sock_hdr_pyld *khdr_pyld;
	dma_addr_t dma_addr;
	u32 len;
};

struct mini_sock_resp {
	struct mini_sock *msock;
	struct list_head list;	/* msock->resp */
	struct list_head glist;	/* mini_sock_resp above */
	bool completed;

	struct mini_sock_hdr_pyld __user *uhdr_pyld;
	struct mini_sock_hdr *khdr;
	dma_addr_t dma_addr;
};

enum mini_sock_conn_state {
	MINI_SOCK_INIT,
	MINI_SOCK_BOUND,
	MINI_SOCK_CLOSED,
	MINI_SOCK_ERROR,
};

struct mini_sock {
	struct mutex lock;
	wait_queue_head_t wq;
	atomic_t changed;

	enum mini_sock_conn_state state;
	u16 sock_type;
	u64 my_cid;
	u64 peer_cid;
	u32 my_port;
	u32 peer_port;

	struct hlist_node port_list;

	struct list_head send;
	int nr_send;
	atomic_t nr_send_inflight;

	struct list_head buf;
	int nr_buf;
	atomic_t nr_buf_inflight;
	atomic_t nr_data;

	struct list_head resp;
	int nr_resp;
	atomic_t nr_resp_inflight;
	atomic_t nr_accepted;
};

static void mini_sock_hdr_set(struct mini_sock_hdr *khdr,
			      uint32_t ret_code, uint32_t state_code)
{
	khdr->ret = cpu_to_le32(ret_code);
	khdr->state = cpu_to_le32(state_code);
}

static void mini_sock_reset_device(void)
{
	/* Rest the device. */
	mini_sock_hdr_pyld->hdr = (struct mini_sock_hdr) {
		.src_cid = cpu_to_le64(MINI_SOCK_CID_ANY),
		.dst_cid = cpu_to_le64(MINI_SOCK_CID_ANY),
		.src_port = cpu_to_le32(MINI_SOCK_PORT_ANY),
		.dst_port = cpu_to_le32(MINI_SOCK_PORT_ANY),
		.len = cpu_to_le32(0),
		.type = cpu_to_le16(MINI_SOCK_TYPE_DGRAM),
		.op = cpu_to_le16(MINI_SOCK_OP_RST),
		.flags = cpu_to_le32(0),
		.ret = cpu_to_le32(MINI_SOCK_SUCCESS),
		.state = cpu_to_le32(MINI_SOCK_STATE_ONREQUEST),
	};
	mini_sock_mmio_request(mini_sock_hdr_pyld);
	WARN_ON_ONCE(le32_to_cpu(READ_ONCE(mini_sock_hdr_pyld->hdr.state)) ==
		     MINI_SOCK_STATE_ONREQUEST ||
		     le32_to_cpu(READ_ONCE(mini_sock_hdr_pyld->hdr.state)) ==
		     MINI_SOCK_STATE_INFLIGHT);
}

static irqreturn_t mini_sock_irq_handler(int irq, void *private)
{
	/* Reap queued send and buf */
	struct mini_sock_recv_buf *tmp_b;
	struct mini_sock_recv_buf *buf;
	struct mini_sock_resp *tmp_r;
	struct mini_sock_resp *resp;
	struct mini_sock_send *tmp_s;
	struct mini_sock_send *send;
	struct mini_sock *msock = NULL;
	unsigned long flags;
	irqreturn_t ret = IRQ_NONE;

	spin_lock_irqsave(&lock, flags);
	list_for_each_entry_safe(send, tmp_s, &mini_sock_send, glist) {
		if (READ_ONCE(send->khdr_pyld->hdr.ret) ==
		    cpu_to_le32(MINI_SOCK_SUCCESS) &&
		    READ_ONCE(send->khdr_pyld->hdr.state) !=
		    cpu_to_le32(MINI_SOCK_STATE_INFLIGHT)) {
			list_del(&send->glist);
			send->completed = true;
			atomic_dec(&send->msock->nr_send_inflight);
			if (msock != send->msock) {
				if (msock) {
					atomic_inc(&msock->changed);
					wake_up_all(&msock->wq);
				}
				msock = send->msock;
			}
			ret = IRQ_HANDLED;
		}
	}
	list_for_each_entry_safe(buf, tmp_b, &mini_sock_buf, glist) {
		if (READ_ONCE(buf->khdr_pyld->hdr.ret) ==
		    cpu_to_le32(MINI_SOCK_SUCCESS) &&
		    READ_ONCE(buf->khdr_pyld->hdr.state) !=
		    cpu_to_le32(MINI_SOCK_STATE_INFLIGHT)) {
			list_del(&buf->glist);
			buf->completed = true;
			atomic_dec(&buf->msock->nr_buf_inflight);
			atomic_inc(&buf->msock->nr_data);
			if (msock != buf->msock) {
				if (msock) {
					atomic_inc(&msock->changed);
					wake_up_all(&msock->wq);
				}
				msock = buf->msock;
			}
			ret = IRQ_HANDLED;
		}
	}
	list_for_each_entry_safe(resp, tmp_r, &mini_sock_resp, glist) {
		if (READ_ONCE(resp->khdr->ret) ==
		    cpu_to_le32(MINI_SOCK_SUCCESS) &&
		    READ_ONCE(resp->khdr->state) !=
		    cpu_to_le32(MINI_SOCK_STATE_INFLIGHT)) {
			list_del(&resp->glist);
			resp->completed = true;
			atomic_dec(&resp->msock->nr_resp_inflight);
			atomic_inc(&resp->msock->nr_accepted);
			if (msock != resp->msock) {
				if (msock) {
					atomic_inc(&msock->changed);
					wake_up_all(&msock->wq);
				}
				msock = resp->msock;
			}
			ret = IRQ_HANDLED;
		}
	}
	if (msock) {
		atomic_inc(&msock->changed);
		wake_up_all(&msock->wq);
	}
	spin_unlock_irqrestore(&lock, flags);
	return ret;
}

static bool mini_sock_changed(struct mini_sock *msock, int changed)
{
	return atomic_read(&msock->changed) != changed;
}

static struct mini_sock *mini_sock_alloc(void)
{
	struct mini_sock *msock;

	msock = kmalloc(sizeof(*msock), GFP_KERNEL_ACCOUNT);
	if (!msock)
		return ERR_PTR(-ENOMEM);

	mutex_init(&msock->lock);
	init_waitqueue_head(&msock->wq);
	atomic_set(&msock->changed, 0);
	msock->state = MINI_SOCK_INIT;
	msock->sock_type = 0;	/* invalid MIIN_SOCK_TYPE_* */
	msock->my_cid = MINI_SOCK_CID_ANY;
	msock->peer_cid = MINI_SOCK_CID_ANY;
	msock->my_port = MINI_SOCK_PORT_ANY;
	msock->peer_port = MINI_SOCK_PORT_ANY;

	INIT_LIST_HEAD(&msock->send);
	msock->nr_send = 0;
	atomic_set(&msock->nr_send_inflight, 0);

	INIT_LIST_HEAD(&msock->buf);
	msock->nr_buf = 0;
	atomic_set(&msock->nr_buf_inflight, 0);
	atomic_set(&msock->nr_data, 0);

	INIT_LIST_HEAD(&msock->resp);
	msock->nr_resp = 0;
	atomic_set(&msock->nr_resp_inflight, 0);

	INIT_HLIST_NODE(&msock->port_list);

	return msock;
}

static int mini_sock_open(struct inode *inode, struct file *filp)
{
	struct mini_sock *msock;

	msock = mini_sock_alloc();
	if (IS_ERR(msock))
		return PTR_ERR(msock);

	filp->private_data = msock;

	/* Don't link msock to mini_socks until port is bound. */
	return 0;
}

static int mini_sock_release(struct inode *inode, struct file *filp)
{
	struct mini_sock *msock = filp->private_data;
	struct mini_sock_recv_buf *tmp_b;
	struct mini_sock_recv_buf *buf;
	struct mini_sock_resp *tmp_r;
	struct mini_sock_resp *resp;
	struct mini_sock_send *tmp_s;
	struct mini_sock_send *send;
	unsigned long flags;

	mutex_lock(&msock->lock);
	if (msock->state == MINI_SOCK_BOUND) {
		/* cancel queued send and buf. */
		mutex_lock(&mutex_lock);
		mini_sock_hdr_pyld->hdr = (struct mini_sock_hdr) {
			.src_cid = cpu_to_le64(msock->my_cid),
			.dst_cid = cpu_to_le64(msock->peer_cid),
			.src_port = cpu_to_le32(msock->my_port),
			.dst_port = cpu_to_le32(msock->peer_port),
			.len = cpu_to_le32(0),
			.type = cpu_to_le16(msock->sock_type),
			.op = cpu_to_le16(MINI_SOCK_OP_SHUTDOWN),
			.flags = cpu_to_le32(0),
			.ret = cpu_to_le32(MINI_SOCK_SUCCESS),
			.state = cpu_to_le32(MINI_SOCK_STATE_ONREQUEST),
		};
		mini_sock_mmio_request(mini_sock_hdr_pyld);
		/* RST is processed immediately. */
		WARN_ON_ONCE(le32_to_cpu(READ_ONCE(mini_sock_hdr_pyld->hdr.state)) ==
			     MINI_SOCK_STATE_ONREQUEST ||
			     le32_to_cpu(READ_ONCE(mini_sock_hdr_pyld->hdr.state)) ==
			     MINI_SOCK_STATE_INFLIGHT);
		mutex_unlock(&mutex_lock);
		msock->state = MINI_SOCK_CLOSED;
	}

	for (;;) {
		int changed;

		spin_lock_irqsave(&lock, flags);
		list_for_each_entry_safe(send, tmp_s, &msock->send, list) {
			if (!send->completed)
				continue;

			list_del(&send->list);
			list_del(&send->glist);
			dma_free_coherent(mini_sock_dev.this_device, send->len,
					  send->khdr_pyld, send->dma_addr);
			kfree(send);
		}

		list_for_each_entry_safe(buf, tmp_b, &msock->buf, list) {
			if (!buf->completed)
				continue;

			list_del(&buf->list);
			list_del(&buf->glist);
			dma_free_coherent(mini_sock_dev.this_device, buf->len,
					  buf->khdr_pyld, buf->dma_addr);
			kfree(buf);
		}

		list_for_each_entry_safe(resp, tmp_r, &msock->resp, list) {
			if (!resp->completed)
				continue;

			list_del(&resp->list);
			list_del(&resp->glist);
			dma_free_coherent(mini_sock_dev.this_device,
					  sizeof(*resp->khdr), resp->khdr,
					  resp->dma_addr);
			kfree(resp);
		}

		if (list_empty(&msock->send) && list_empty(&msock->buf) &&
		    list_empty(&msock->resp))
			break;

		changed = atomic_read(&msock->changed);
		spin_unlock_irqrestore(&lock, flags);
		mutex_unlock(&msock->lock);
		wait_event_interruptible(msock->wq, mini_sock_changed(msock, changed));
		mutex_lock(&msock->lock);
	}

	if (!hlist_unhashed(&msock->port_list))
		hlist_del(&msock->port_list);
	spin_unlock_irqrestore(&lock, flags);

	mutex_unlock(&msock->lock);
	kfree(filp->private_data);
	filp->private_data = NULL;
	return 0;
}

static __poll_t mini_sock_poll(struct file *filp, poll_table *wait)
{
	struct mini_sock *msock = filp->private_data;
	unsigned long flags;
	__poll_t ret = 0;

	poll_wait(filp, &msock->wq, wait);

	mutex_lock(&msock->lock);
	if (msock->state != MINI_SOCK_BOUND)
		goto out;

	spin_lock_irqsave(&lock, flags);
	if (atomic_read(&msock->nr_data) > 0 || atomic_read(&msock->nr_accepted) > 0)
		ret |= EPOLLIN | EPOLLRDNORM;
	if (!atomic_read(&msock->nr_send_inflight))
		ret |= EPOLLOUT;
	spin_unlock_irqrestore(&lock, flags);

out:
	mutex_unlock(&msock->lock);
	return ret;
}

static int mini_sock_ioctl_op_config(struct mini_sock *msock,
				     struct mini_sock_hdr_pyld __user *uhdr_pyld,
				     struct mini_sock_hdr *khdr)
{
	struct mini_sock_config_data config;
	unsigned long len = 0;
	void *data = NULL;
	__le64 tmp;

	if (khdr->src_cid != cpu_to_le64(MINI_SOCK_CID_ANY) ||
	    khdr->dst_cid != cpu_to_le64(MINI_SOCK_CID_ANY) ||
	    khdr->dst_port != cpu_to_le32(MINI_SOCK_PORT_ANY) ||
	    khdr->src_port != cpu_to_le32(MINI_SOCK_PORT_ANY))
		return -EINVAL;
	if (le32_to_cpu(khdr->len) <= sizeof(config))
		return -E2BIG;
	if (khdr->flags != cpu_to_le32(MINI_SOCK_CONFIG_GET))
		return -EINVAL;
	if (copy_from_user(&config, uhdr_pyld->payload, sizeof(config)))
		return -EFAULT;

	switch(le64_to_cpu(config.key)) {
	case MINI_SOCK_CONFIG_CID:
		tmp = cpu_to_le64(guest_cid);
		data = &tmp;
		len = sizeof(guest_cid);
		break;
	case MINI_SOCK_CONFIG_MTU:
		tmp = cpu_to_le64(mini_sock_mtu);
		data = &tmp;
		len = sizeof(mini_sock_mtu);
		break;
	case MINI_SOCK_CONFIG_MSI:
	default:
		break;
	}

	if (!data)
		return -ENOENT;
	if (khdr->len < sizeof(config) + len)
		return -E2BIG;
	if (copy_to_user(uhdr_pyld->payload + sizeof(config), data, len))
		return -EFAULT;

	mini_sock_hdr_set(khdr, MINI_SOCK_SUCCESS_DONE, MINI_SOCK_STATE_SUCCESS);
	return 0;
}

static int mini_sock_ioctl_op_request(struct mini_sock *msock,
				      struct mini_sock_hdr *khdr)
{
	struct mini_sock *tmp;
	unsigned long flags;
	u32 src_port;
	int r = 0;

	if (khdr->flags != cpu_to_le32(0))
		return -EINVAL;

	if (khdr->src_cid != cpu_to_le64(guest_cid))
		return -EINVAL;
	/*
	 * Server case: accept data from any address and must use known port.
	 * Client case: must specify server address.
	 */
	if (!((khdr->dst_cid == cpu_to_le64(MINI_SOCK_CID_ANY) &&
	       khdr->dst_port == cpu_to_le32(MINI_SOCK_PORT_ANY) &&
	       khdr->src_port != cpu_to_le32(MINI_SOCK_PORT_ANY)) ||
	      (khdr->dst_cid != cpu_to_le64(MINI_SOCK_CID_ANY) &&
	       khdr->dst_port != cpu_to_le32(MINI_SOCK_PORT_ANY))))
		return -EINVAL;
	src_port = le32_to_cpu(khdr->src_port);

	mutex_lock(&msock->lock);
	if (msock->state != MINI_SOCK_INIT) {
		r = -EINVAL;
		goto out;
	}

	/*
	 * src port: Check only src port conflict, and don't check the src/dst
	 * cid/port de-duplication similar to unix dgram src address.
	 */
	spin_lock_irqsave(&lock, flags);
	if (src_port != MINI_SOCK_PORT_ANY) {
		r = 0;
		hlist_for_each_entry(tmp, &sorted_in_port, port_list) {
			if (src_port > tmp->my_port)
				continue;
			if (tmp->my_port == src_port) {
				r = -EADDRINUSE;
				break;
			}
			break;
		}
	} else {
		/*
		 * Find an available ephemeral port.
		 * TODO: Optimize or invent more appropreate data structure.
		 */
		u32 port = last_port + 1;

		r = 0;
		WARN_ON_ONCE(port == MINI_SOCK_PORT_MAX);
		hlist_for_each_entry(tmp, &sorted_in_port, port_list) {
			if (port > tmp->my_port)
				continue;
			if (port == tmp->my_port) {
				port++;
				if (port == MINI_SOCK_PORT_MAX) {
					r = -EADDRINUSE;
					break;
				}
				continue;
			}
			break;
		}
		if (r == -EADDRINUSE) {
			port = 0;
			hlist_for_each_entry(tmp, &sorted_in_port, port_list) {
				if (port < tmp->my_port) {
					r = 0;
					break;
				}
				if (port == tmp->my_port) {
					port++;
					if (port == last_port) {
						r = -EADDRINUSE;
						break;
					}
					continue;
				}
				if (tmp->my_port >= last_port)
					break;
				continue;
			}
		}
		if (!r) {
			src_port = port;
			last_port = port;
		}
		if (last_port == MINI_SOCK_PORT_MAX)
			last_port = 0;
	}
	if (!r) {
		msock->state = MINI_SOCK_BOUND;
		msock->sock_type = le16_to_cpu(khdr->type);
		msock->peer_cid = le64_to_cpu(khdr->dst_cid);
		msock->peer_port = le32_to_cpu(khdr->dst_port);
		msock->my_cid = le64_to_cpu(khdr->src_cid);
		msock->my_port = src_port;
		if (tmp)
			hlist_add_before(&msock->port_list, &tmp->port_list);
		else
			hlist_add_head(&msock->port_list, &sorted_in_port);
	}
	spin_unlock_irqrestore(&lock, flags);
out:
	if (r) {
		mutex_unlock(&msock->lock);
		return r;
	}

	mutex_lock(&mutex_lock);
	mini_sock_hdr_pyld->hdr = (struct mini_sock_hdr) {
		.src_cid = cpu_to_le64(msock->my_cid),
		.dst_cid = cpu_to_le64(msock->peer_cid),
		.src_port = cpu_to_le32(msock->my_port),
		.dst_port = cpu_to_le32(msock->peer_port),
		.len = cpu_to_le32(0),
		.type = cpu_to_le16(msock->sock_type),
		.op = cpu_to_le16(MINI_SOCK_OP_REQUEST),
		.flags = cpu_to_le32(0),
		.ret = cpu_to_le32(MINI_SOCK_SUCCESS),
		.state = cpu_to_le32(MINI_SOCK_STATE_ONREQUEST),
	};
	mini_sock_mmio_request(mini_sock_hdr_pyld);
	/* REQUEST is processed immediately. */
	memcpy(&khdr->_state, &mini_sock_hdr_pyld->hdr._state, sizeof(khdr->_state));
	WARN_ON_ONCE(le32_to_cpu(khdr->state) == MINI_SOCK_STATE_ONREQUEST ||
		     le32_to_cpu(khdr->state) == MINI_SOCK_STATE_INFLIGHT);
	mutex_unlock(&mutex_lock);

	if (khdr->state == cpu_to_le32(MINI_SOCK_STATE_ERROR)) {
		r = le32_to_cpu(khdr->ret);
		msock->state = MINI_SOCK_ERROR;
		spin_lock_irqsave(&lock, flags);
		hlist_del_init(&msock->port_list);
		spin_unlock_irqrestore(&lock, flags);
	}
	mutex_unlock(&msock->lock);
	if (!r && khdr->state == cpu_to_le32(MINI_SOCK_STATE_SUCCESS)) {
		khdr->src_port = cpu_to_le32(src_port);
		mini_sock_hdr_set(khdr, MINI_SOCK_SUCCESS_DONE, MINI_SOCK_STATE_SUCCESS);
	}
	return r;
}

static struct file_operations mini_sock_ops;

static int mini_sock_socket_accept(struct mini_sock *msock,
				   struct mini_sock_hdr *khdr)
{
	struct mini_sock *accept;
	struct file *file;
	int fd;

	accept = mini_sock_alloc();
	if (IS_ERR(accept)) {
		return PTR_ERR(accept);
	}

	accept->state = MINI_SOCK_BOUND;
	accept->sock_type = msock->sock_type;
	accept->my_cid = msock->my_cid;
	accept->my_port = msock->my_port;
	accept->peer_cid = le64_to_cpu(khdr->dst_cid);
	accept->peer_port = le32_to_cpu(khdr->dst_port);

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		kfree(accept);
		return fd;
	}

	file = anon_inode_getfile("mini-sock", &mini_sock_ops, accept, O_RDWR);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		kfree(accept);
		return PTR_ERR(file);
	}

	fd_install(fd, file);
	return fd;
}

static int mini_sock_khdr_sanitize_state(struct mini_sock_hdr *khdr)
{
	int ret = le32_to_cpu(khdr->ret);

	switch (le32_to_cpu(khdr->state)) {
	case MINI_SOCK_STATE_SUCCESS:
		if (ret != MINI_SOCK_SUCCESS)
			break;
		mini_sock_hdr_set(khdr, MINI_SOCK_SUCCESS_DONE,
				  MINI_SOCK_STATE_SUCCESS);
		return 0;
	case MINI_SOCK_STATE_INFLIGHT:
		if (ret != MINI_SOCK_SUCCESS)
			break;
		return 0;
	case MINI_SOCK_STATE_ERROR:
		if (ret >= 0)
			break;
		return ret;
	case MINI_SOCK_STATE_ONREQUEST:
	default:
		break;
	}

	WARN_ON_ONCE(1);
	mini_sock_hdr_set(khdr, -EIO, MINI_SOCK_STATE_ERROR);
	return -EIO;
}

static int mini_sock_ioctl_op_response(struct mini_sock *msock,
				       struct mini_sock_hdr_pyld __user *uhdr_pyld,
				       struct mini_sock_hdr *khdr)
{
	struct mini_sock_resp *resp = NULL;
	struct mini_sock_hdr *khdr_dma = NULL;
	dma_addr_t dma_addr;
	unsigned long flags;
	int r = 0;

	if (khdr->len != cpu_to_le32(0) ||
	    khdr->type != cpu_to_le32(MINI_SOCK_TYPE_STREAM) ||
	    khdr->flags != cpu_to_le32(0) ||
	    khdr->ret != cpu_to_le32(MINI_SOCK_SUCCESS) ||
	    khdr->state != cpu_to_le32(MINI_SOCK_STATE_ONREQUEST))
		return -EINVAL;
	if (khdr->dst_cid != cpu_to_le64(MINI_SOCK_CID_ANY) ||
	    khdr->dst_port != cpu_to_le32(MINI_SOCK_PORT_ANY))
		return -EINVAL;

	khdr_dma = dma_alloc_coherent(mini_sock_dev.this_device, sizeof(*khdr),
				      &dma_addr, GFP_KERNEL_ACCOUNT);
	if (!khdr_dma)
		return -ENOMEM;
	*khdr_dma = *khdr;
	khdr_dma->src_cid = cpu_to_le64(guest_cid);
	khdr_dma->src_port = cpu_to_le32(msock->my_port);
	mini_sock_hdr_set(khdr_dma, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_ONREQUEST);

	resp = kmalloc(sizeof(*resp), GFP_KERNEL_ACCOUNT);
	if (!resp) {
		r = -ENOMEM;
		goto error;
	}
	*resp = (struct mini_sock_resp) {
		.msock = msock,
		.completed = false,
		.uhdr_pyld = uhdr_pyld,
		.khdr = khdr_dma,
		.dma_addr = dma_addr,
	};

	mutex_lock(&msock->lock);
	/* Is this server listening socket? */
	if (msock->state != MINI_SOCK_BOUND) {
		r = -EINVAL;
		goto error_unlock;
	}
	if (msock->sock_type != MINI_SOCK_TYPE_STREAM) {
		r = -EINVAL;
		goto error_unlock;
	}
	/* Is this listening server socket? */
	if (!(msock->peer_cid == MINI_SOCK_CID_ANY &&
	      msock->peer_port == MINI_SOCK_PORT_ANY)) {
		r = -EINVAL;
		goto error_unlock;
	}

	spin_lock_irqsave(&lock, flags);
	if (msock->nr_resp > MINI_SOCK_QUEUE_MAX) {
		r = -ENOBUFS;
		spin_unlock_irqrestore(&lock, flags);
		goto error_unlock;
	}
	list_add_tail(&resp->list, &msock->resp);
	list_add_tail(&resp->glist, &mini_sock_resp);
	msock->nr_resp++;
	spin_unlock_irqrestore(&lock, flags);

	mini_sock_mmio_request(khdr_dma);
	memcpy(khdr, khdr_dma, sizeof(*khdr));
	WARN_ON_ONCE(le32_to_cpu(khdr->state) == MINI_SOCK_STATE_ONREQUEST ||
		     le32_to_cpu(khdr->state) == MINI_SOCK_STATE_INFLIGHT);

	spin_lock_irqsave(&lock, flags);
	if (!resp->completed) {
		if (khdr->ret == cpu_to_le32(MINI_SOCK_SUCCESS) &&
		    khdr->state == cpu_to_le32(MINI_SOCK_STATE_INFLIGHT)) {
			/* Keep this send request for interrupt handler. */
			khdr_dma = NULL;
			resp = NULL;
			mini_sock_hdr_set(khdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_INFLIGHT);
		} else {
			list_del(&resp->list);
			list_del(&resp->glist);
			msock->nr_resp--;
		}
		r = mini_sock_khdr_sanitize_state(khdr);
	} else {
		/* Someone already consumed this.  Don't touch. */
		khdr_dma = NULL;
		resp = NULL;
		mini_sock_hdr_set(khdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
	}
	spin_unlock_irqrestore(&lock, flags);

error_unlock:
	mutex_unlock(&msock->lock);
error:
	if (!r && resp)
		r = mini_sock_socket_accept(msock, khdr);

	kfree(resp);
	if (khdr_dma)
		dma_free_coherent(mini_sock_dev.this_device, sizeof(*khdr_dma), khdr_dma, dma_addr);
	return r;
}

static int mini_sock_ioctl_op_shutdown(struct mini_sock *msock,
				       struct mini_sock_hdr *khdr)
{
	int r = 0;
	enum mini_sock_conn_state new_state;

	if (khdr->flags != cpu_to_le32(0))
		return -EINVAL;

	if (khdr->src_cid != cpu_to_le64(guest_cid))
		return -EINVAL;

	mutex_lock(&msock->lock);
	if (msock->state != MINI_SOCK_BOUND) {
		r = -ENOTCONN;
		goto out;
	}
	if (khdr->type != cpu_to_le32(msock->sock_type)) {
		r = -EINVAL;
		goto out;
	}
	if (khdr->src_port != cpu_to_le32(msock->my_port)) {
		r = -EBADF;
		goto out;
	}
	if (msock->peer_cid == MINI_SOCK_CID_ANY) {
		/* server case*/
		if (khdr->dst_cid != cpu_to_le64(MINI_SOCK_CID_ANY) &&
		    khdr->dst_port != cpu_to_le32(MINI_SOCK_PORT_ANY))
			new_state = MINI_SOCK_BOUND;
		else if (khdr->dst_cid == cpu_to_le64(MINI_SOCK_CID_ANY) &&
			 khdr->dst_port == cpu_to_le32(MINI_SOCK_PORT_ANY))
			new_state = MINI_SOCK_CLOSED;
		else {
			r = -EINVAL;
			goto out;
		}
	} else {
		/* client case */
		if (khdr->dst_cid == cpu_to_le64(msock->peer_cid) &&
		    khdr->dst_port == cpu_to_le32(msock->peer_port))
			new_state = MINI_SOCK_CLOSED;
		else {
			r = -EINVAL;
			goto out;
		}
	}
	mutex_lock(&mutex_lock);
	mini_sock_hdr_pyld->hdr = (struct mini_sock_hdr) {
		.src_cid = cpu_to_le64(msock->my_cid),
		.dst_cid = khdr->dst_cid,
		.src_port = cpu_to_le32(msock->my_port),
		.dst_port = khdr->dst_port,
		.len = cpu_to_le32(0),
		.type = cpu_to_le16(msock->sock_type),
		.op = cpu_to_le16(MINI_SOCK_OP_SHUTDOWN),
		.flags = cpu_to_le32(0),
		.ret = cpu_to_le32(MINI_SOCK_SUCCESS),
		.state = cpu_to_le32(MINI_SOCK_STATE_ONREQUEST),
	};
	mini_sock_mmio_request(mini_sock_hdr_pyld);
	/* VMM is expected to process SHUTDOWN synchronously. */
	memcpy(&khdr->_state, &mini_sock_hdr_pyld->hdr._state, sizeof(khdr->_state));
	WARN_ON_ONCE(le32_to_cpu(khdr->state) == MINI_SOCK_STATE_ONREQUEST ||
		     le32_to_cpu(khdr->state) == MINI_SOCK_STATE_INFLIGHT);
	r = le32_to_cpu(khdr->ret);
	mutex_unlock(&mutex_lock);
	if (!r)
		msock->state = new_state;
out:
	mutex_unlock(&msock->lock);
	if (!r && khdr->state == cpu_to_le32(MINI_SOCK_STATE_SUCCESS))
		mini_sock_hdr_set(khdr, MINI_SOCK_SUCCESS_DONE, MINI_SOCK_STATE_SUCCESS);
	/* msock->send and msock->buf will be reaped by interrupt handler. */
	return r;
}

static int mini_sock_ioctl_op_send(struct mini_sock *msock,
				   struct mini_sock_hdr_pyld __user *uhdr_pyld,
				   struct mini_sock_hdr *khdr)
{
	struct mini_sock_hdr_pyld *khdr_pyld = NULL;
	struct mini_sock_send *send = NULL;
	unsigned long flags;
	dma_addr_t dma_addr;
	u32 len = le32_to_cpu(khdr->len);
	int r = 0;

	if (len > mini_sock_mtu)
		return -EMSGSIZE;

	khdr_pyld = dma_alloc_coherent(mini_sock_dev.this_device, len + sizeof(*khdr),
				       &dma_addr, GFP_KERNEL_ACCOUNT);
	if (!khdr_pyld)
		return -ENOMEM;

	khdr_pyld->hdr = *khdr;
	if (copy_from_user(khdr_pyld->payload, uhdr_pyld->payload, len)) {
		r = -EFAULT;
		goto error;
	}
	khdr_pyld->hdr.src_cid = cpu_to_le64(guest_cid);
	khdr_pyld->hdr.src_port = cpu_to_le64(msock->my_port);
	mini_sock_hdr_set(&khdr_pyld->hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_ONREQUEST);

	send = kmalloc(sizeof(*send), GFP_KERNEL_ACCOUNT);
	if (!send) {
		r = -ENOMEM;
		goto error;
	}
	send->msock = msock;
	send->uhdr_pyld = uhdr_pyld;
	send->khdr_pyld = khdr_pyld;
	send->len = len;
	send->dma_addr = dma_addr;
	send->completed = false;

	mutex_lock(&msock->lock);
	if (unlikely(msock->state != MINI_SOCK_BOUND)) {
		r = -ENOTCONN;
		goto error_unlock;
	}
	if (unlikely(khdr->type != cpu_to_le16(msock->sock_type))) {
		r = -EINVAL;
		goto error_unlock;
	}
	if (!((MINI_SOCK_CID_ANY == msock->peer_cid ||
	       khdr->dst_cid == cpu_to_le64(msock->peer_cid)) &&
	      (MINI_SOCK_PORT_ANY == msock->peer_port ||
	       khdr->dst_port == cpu_to_le32(msock->peer_port)))) {
		r = -EBADF;
		goto error_unlock;
	}

	spin_lock_irqsave(&lock, flags);
	if (msock->nr_send > MINI_SOCK_QUEUE_MAX) {
		r = -ENOBUFS;
		spin_unlock_irqrestore(&lock, flags);
		mutex_unlock(&msock->lock);
		goto error;
	}
	list_add_tail(&send->list, &msock->send);
	list_add_tail(&send->glist, &mini_sock_send);
	msock->nr_send++;
	spin_unlock_irqrestore(&lock, flags);

	mini_sock_mmio_request(khdr_pyld);
	memcpy(khdr, &khdr_pyld->hdr, sizeof(*khdr));
	WARN_ON_ONCE(le32_to_cpu(khdr->state) == MINI_SOCK_STATE_ONREQUEST);

	spin_lock_irqsave(&lock, flags);
	if (!send->completed) {
		if (khdr->ret == cpu_to_le32(MINI_SOCK_SUCCESS) &&
		    khdr->state == cpu_to_le32(MINI_SOCK_STATE_INFLIGHT)) {
			/* Keep this send request for interrupt handler. */
			khdr_pyld = NULL;
			send = NULL;
		} else {
			list_del(&send->list);
			list_del(&send->glist);
			msock->nr_send--;
		}
		r = mini_sock_khdr_sanitize_state(khdr);
	} else {
		/* Someone already consumed this.  Don't touch. */
		khdr_pyld = NULL;
		send = NULL;
		mini_sock_hdr_set(khdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
	}
	spin_unlock_irqrestore(&lock, flags);
error_unlock:
	mutex_unlock(&msock->lock);
error:
	kfree(send);
	if (khdr_pyld)
		dma_free_coherent(mini_sock_dev.this_device, len, khdr_pyld, dma_addr);
	return r;
}

static int mini_sock_ioctl_op_buf(struct mini_sock *msock,
				  struct mini_sock_hdr_pyld __user *uhdr_pyld,
				  struct mini_sock_hdr *khdr)
{
	struct mini_sock_hdr_pyld *khdr_pyld = NULL;
	struct mini_sock_recv_buf *buf = NULL;
	dma_addr_t dma_addr;
	unsigned long flags;
	u32 len = le32_to_cpu(khdr->len);
	int r = 0;

	if (len > mini_sock_mtu)
		return -EMSGSIZE;

	khdr_pyld = dma_alloc_coherent(mini_sock_dev.this_device, len + sizeof(*khdr),
				       &dma_addr, GFP_KERNEL_ACCOUNT);
	if (!khdr_pyld) {
		r = -ENOMEM;
		goto error;
	}
	khdr_pyld->hdr = *khdr;
	khdr_pyld->hdr.dst_cid = cpu_to_le64(guest_cid);
	khdr_pyld->hdr.dst_port = cpu_to_le32(msock->my_port);
	mini_sock_hdr_set(&khdr_pyld->hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_ONREQUEST);

	buf = kmalloc(sizeof(*buf), GFP_KERNEL_ACCOUNT);
	if (!buf)
		return -ENOMEM;
	buf->msock = msock;
	buf->uhdr_pyld = uhdr_pyld;
	buf->khdr_pyld = khdr_pyld;
	buf->dma_addr = dma_addr;
	buf->len = len;
	buf->completed = false;

	mutex_lock(&msock->lock);
	if (msock->state != MINI_SOCK_BOUND) {
		r = -ENOTCONN;
		mutex_unlock(&msock->lock);
		goto error;
	}
	if (unlikely(khdr->type != cpu_to_le16(msock->sock_type))) {
		r = -EINVAL;
		mutex_unlock(&msock->lock);
		goto error;
	}
	if (!((MINI_SOCK_CID_ANY == msock->peer_cid ||
	       khdr->src_cid == cpu_to_le64(msock->peer_cid)) &&
	      (MINI_SOCK_PORT_ANY == msock->peer_port ||
	       khdr->src_port == cpu_to_le32(msock->peer_port)))) {
		r = -EBADF;
		mutex_unlock(&msock->lock);
		goto error;
	}

	spin_lock_irqsave(&lock, flags);
	if (msock->nr_buf > MINI_SOCK_QUEUE_MAX) {
		r = -ENOMEM;
		spin_unlock_irqrestore(&lock, flags);
		mutex_unlock(&msock->lock);
		goto error;
	}
	list_add_tail(&buf->list, &msock->buf);
	list_add_tail(&buf->glist, &mini_sock_buf);
	msock->nr_buf++;
	atomic_inc(&msock->nr_buf_inflight);
	spin_unlock_irqrestore(&lock, flags);

	mini_sock_mmio_request(khdr_pyld);
	memcpy(khdr, &khdr_pyld->hdr, sizeof(*khdr));
	WARN_ON_ONCE(le32_to_cpu(khdr->state) == MINI_SOCK_STATE_ONREQUEST);

	spin_lock_irqsave(&lock, flags);
	if (!buf->completed) {
		if (khdr->ret == cpu_to_le32(MINI_SOCK_SUCCESS) &&
		    khdr->state == cpu_to_le32(MINI_SOCK_STATE_INFLIGHT)) {
			/* Keep this send request for interrupt handler. */
			buf = NULL;
			khdr_pyld = NULL;
		} else {
			list_del(&buf->list);
			list_del(&buf->glist);
			msock->nr_buf--;
			atomic_dec(&msock->nr_buf_inflight);
		}
		r = mini_sock_khdr_sanitize_state(khdr);
	} else {
		/* Someone already consumed it. Don't touch. */
		buf = NULL;
		khdr_pyld = NULL;
		mini_sock_hdr_set(khdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
	}
	spin_unlock_irqrestore(&lock, flags);
	mutex_unlock(&msock->lock);

error:
	if (!r && buf && khdr->ret == cpu_to_le32(MINI_SOCK_SUCCESS_DONE) &&
	    khdr->state == cpu_to_le32(MINI_SOCK_STATE_SUCCESS)) {
		len = le32_to_cpu(khdr->len);
		if (len > buf->len)
			r = -EMSGSIZE;
		else if (copy_to_user(uhdr_pyld->payload,
				      khdr_pyld->payload, len))
			r = -EFAULT;
	}
	kfree(buf);
	if (khdr_pyld)
		dma_free_coherent(mini_sock_dev.this_device, len, khdr_pyld,
				  dma_addr);
	return r;
}

static int mini_sock_ioctl_op_rw(struct mini_sock *msock,
				 struct mini_sock_hdr_pyld __user *uhdr_pyld,
				 struct mini_sock_hdr *khdr)
{
	switch (le64_to_cpu(khdr->flags)) {
	case MINI_SOCK_RW_SEND:
		return mini_sock_ioctl_op_send(msock, uhdr_pyld, khdr);
	case MINI_SOCK_RW_RECV:
		return mini_sock_ioctl_op_buf(msock, uhdr_pyld, khdr);
	default:
		return -EINVAL;
	}
}

static long mini_sock_ioctl_post(struct mini_sock *msock,
				 struct mini_sock_hdr_pyld __user *uhdr_pyld)
{
	struct mini_sock_hdr khdr;
	int r;

	if (copy_from_user(&khdr, &uhdr_pyld->hdr, sizeof(khdr)))
		return -EFAULT;
	if (khdr.type != cpu_to_le16(MINI_SOCK_TYPE_DGRAM) &&
	    khdr.type != cpu_to_le16(MINI_SOCK_TYPE_STREAM))
		return -EINVAL;
	if (khdr.ret != cpu_to_le32(MINI_SOCK_SUCCESS))
		return -EINVAL;
	if (khdr.state != cpu_to_le32(MINI_SOCK_STATE_ONREQUEST))
		return -EINVAL;

	switch (le32_to_cpu(khdr.op)) {
	case MINI_SOCK_OP_CONFIG:
		r =  mini_sock_ioctl_op_config(msock, uhdr_pyld, &khdr);
		break;
	case MINI_SOCK_OP_REQUEST:
		r =  mini_sock_ioctl_op_request(msock, &khdr);
		break;
	case MINI_SOCK_OP_RESPONSE:
		r = mini_sock_ioctl_op_response(msock, uhdr_pyld, &khdr);
		break;
	case MINI_SOCK_OP_SHUTDOWN:
		r =  mini_sock_ioctl_op_shutdown(msock, &khdr);
		break;
	case MINI_SOCK_OP_RW:
		r = mini_sock_ioctl_op_rw(msock, uhdr_pyld, &khdr);
		break;
	default:
		r = -EINVAL;
		break;
	}
	if (r < 0)
		mini_sock_hdr_set(&khdr, r, MINI_SOCK_STATE_ERROR);
	if (copy_to_user(&uhdr_pyld->hdr, &khdr, sizeof(uhdr_pyld->hdr)))
		return -EFAULT;
	return r;
}

static int mini_sock_ioctl_complete_send(struct mini_sock *msock,
					 struct mini_sock_send *send,
					 unsigned long flags)
	__releases(&mock->lock) __releases(&lock)
{
	int r = 0;

	list_del(&send->list);
	/* The interrupt handler does list_del(&send->glist). */
	msock->nr_send--;
	spin_unlock_irqrestore(&lock, flags);
	mutex_unlock(&msock->lock);

	if (copy_to_user(&send->uhdr_pyld->hdr, &send->khdr_pyld->hdr,
			 sizeof(send->uhdr_pyld->hdr)))
		r = -EFAULT;
	dma_free_coherent(mini_sock_dev.this_device,
			  send->len, send->khdr_pyld, send->dma_addr);
	kfree(send);
	return r;
}

static int mini_sock_ioctl_complete_recv_buf(struct mini_sock *msock,
					     struct mini_sock_recv_buf *buf,
					     unsigned long flags)
	__releases(&mock->lock) __releases(&lock)
{
	struct mini_sock_hdr khdr;
	int r = 0;

	list_del(&buf->list);
	/* The interrutp handler does list_del(&buf->glist). */
	msock->nr_buf--;
	atomic_dec(&msock->nr_data);
	spin_unlock_irqrestore(&lock, flags);
	mutex_unlock(&msock->lock);

	memcpy(&khdr, &buf->khdr_pyld->hdr, sizeof(khdr));
	if (khdr.ret == cpu_to_le32(MINI_SOCK_SUCCESS) &&
	    khdr.state == cpu_to_le32(MINI_SOCK_STATE_SUCCESS)) {
		u32 len = le32_to_cpu(khdr.len);
		if (len > buf->len)
			mini_sock_hdr_set(&khdr, -EMSGSIZE, MINI_SOCK_STATE_ERROR);
		else if (copy_to_user(buf->uhdr_pyld->payload,
				      buf->khdr_pyld->payload, len))
			mini_sock_hdr_set(&khdr, -EFAULT, MINI_SOCK_STATE_ERROR);
	} else {
		if (WARN_ON_ONCE(khdr.state != cpu_to_le32(MINI_SOCK_STATE_ERROR)))
			mini_sock_hdr_set(&khdr, -EIO, MINI_SOCK_STATE_ERROR);
	}
	dma_free_coherent(mini_sock_dev.this_device, buf->len,
			  buf->khdr_pyld, buf->dma_addr);
	if (copy_to_user(&buf->uhdr_pyld->hdr, &khdr, sizeof(buf->uhdr_pyld->hdr)))
		r = -EFAULT;
	kfree(buf);
	return r;
}

static int mini_sock_ioctl_complete_resp(struct mini_sock *msock,
					 struct mini_sock_resp *resp,
					 unsigned long flags)
	__releases(&mock->lock) __releases(&lock)
{
	struct mini_sock_hdr khdr;
	int r = 0;

	list_del(&resp->list);
	/* The interrupt handler does list_del(&resp->glist). */
	msock->nr_resp--;
	atomic_dec(&msock->nr_accepted);
	spin_unlock_irqrestore(&lock, flags);
	mutex_unlock(&msock->lock);

	memcpy(&khdr, resp->khdr, sizeof(khdr));
	dma_free_coherent(mini_sock_dev.this_device,
			  sizeof(*resp->khdr), resp->khdr, resp->dma_addr);

	if (khdr.ret == cpu_to_le32(MINI_SOCK_SUCCESS) &&
	    khdr.state == cpu_to_le32(MINI_SOCK_STATE_SUCCESS)) {
		r = mini_sock_socket_accept(msock, &khdr);
	}

	if (copy_to_user(&resp->uhdr_pyld->hdr, &khdr, sizeof(khdr)))
		r = -EFAULT;
	kfree(resp);
	return r;
}

static bool mini_sock_completable(struct mini_sock *msock)
{
	bool r;

	mutex_lock(&msock->lock);
	r = atomic_read(&msock->nr_send_inflight) < msock->nr_send ||
		atomic_read(&msock->nr_buf_inflight) < msock->nr_buf ||
		atomic_read(&msock->nr_resp_inflight) < msock->nr_resp;
	mutex_unlock(&msock->lock);
	return r;
}

static int mini_sock_ioctl_complete_any(struct mini_sock *msock,
					struct mini_sock_hdr_pyld __user **uhdr_pyld_p)
{
	struct mini_sock_hdr_pyld __user *uhdr_pyld = NULL;
	struct mini_sock_recv_buf *buf;
	struct mini_sock_send *send;
	struct mini_sock_resp *resp;
	unsigned long flags;
	int r = 0;

	r = wait_event_interruptible(msock->wq, mini_sock_completable(msock));
	if (r)
		return r;

	mutex_lock(&msock->lock);
	spin_lock_irqsave(&lock, flags);
	if (atomic_read(&msock->nr_send_inflight) < msock->nr_send) {
		list_for_each_entry(send, &msock->send, list) {
			if (!send->completed)
				continue;

			uhdr_pyld = send->uhdr_pyld;
			r = mini_sock_ioctl_complete_send(msock, send, flags);
			goto out;
		}
	}

	if (atomic_read(&msock->nr_buf_inflight) < msock->nr_buf) {
		list_for_each_entry(buf, &msock->buf, list) {
			if (!buf->completed)
				continue;

			uhdr_pyld = buf->uhdr_pyld;
			r = mini_sock_ioctl_complete_recv_buf(msock, buf, flags);
			goto out;
		}
	}

	if (atomic_read(&msock->nr_resp_inflight) < msock->nr_resp) {
		list_for_each_entry(buf, &msock->resp, list) {
			if (!resp->completed)
				continue;

			uhdr_pyld = resp->uhdr_pyld;
			r = mini_sock_ioctl_complete_resp(msock, resp, flags);
			goto out;
		}
	}

	if (!uhdr_pyld)
		r = -ENOENT;
	spin_unlock_irqrestore(&lock, flags);
	mutex_unlock(&msock->lock);

out:
	if (!r && !uhdr_pyld) {
		if (copy_to_user(uhdr_pyld_p, &uhdr_pyld, sizeof(uhdr_pyld)))
			r = -EFAULT;
	}
	return r;
}

static int mini_sock_ioctl_complete(struct mini_sock *msock,
				    struct mini_sock_hdr_pyld __user **uhdr_pyld_p)
{
	struct mini_sock_hdr_pyld __user *uhdr_pyld;
	struct mini_sock_recv_buf *buf;
	struct mini_sock_send *send;
	struct mini_sock_resp *resp;
	unsigned long flags;
	int r = 0;

	if (copy_from_user(&uhdr_pyld, uhdr_pyld_p, sizeof(uhdr_pyld)))
		return -EFAULT;

	if (uhdr_pyld == MINI_SOCK_COMPLETE_ANY)
		return mini_sock_ioctl_complete_any(msock, uhdr_pyld_p);

retry:
	mutex_lock(&msock->lock);
	list_for_each_entry(send, &msock->send, list) {
		if (send->uhdr_pyld != uhdr_pyld)
			continue;

		spin_lock_irqsave(&lock, flags);
		if (!send->completed) {
			int changed = atomic_read(&msock->changed);

			spin_unlock_irqrestore(&lock, flags);
			mutex_unlock(&msock->lock);
			r = wait_event_interruptible(msock->wq, mini_sock_changed(msock, changed));
			if (r)
				return r;
			goto retry;
		}

		return mini_sock_ioctl_complete_send(msock, send, flags);
	}

	list_for_each_entry(buf, &msock->buf, list) {
		if (buf->uhdr_pyld != uhdr_pyld)
			continue;

		spin_lock_irqsave(&lock, flags);
		if (!buf->completed) {
			int changed = atomic_read(&msock->changed);

			spin_unlock_irqrestore(&lock, flags);
			mutex_unlock(&msock->lock);
			r = wait_event_interruptible(msock->wq, mini_sock_changed(msock, changed));
			if (r)
				return r;
			goto retry;
		}

		return mini_sock_ioctl_complete_recv_buf(msock, buf, flags);
	}

	list_for_each_entry(resp, &msock->resp, list) {
		if (resp->uhdr_pyld != uhdr_pyld)
			continue;

		spin_lock_irqsave(&lock, flags);
		if (!resp->completed) {
			int changed = atomic_read(&msock->changed);

			spin_unlock_irqrestore(&lock, flags);
			mutex_unlock(&msock->lock);
			r = wait_event_interruptible(msock->wq, mini_sock_changed(msock, changed));
			if (r)
				return r;
			goto retry;
		}

		return mini_sock_ioctl_complete_resp(msock, resp, flags);
	}
	mutex_unlock(&msock->lock);
	return -ENOENT;
}

static long mini_sock_ioctl(struct file *filp, unsigned int ioctl,
			    unsigned long arg)
{
	struct mini_sock *msock = filp->private_data;

	switch (ioctl) {
	case MINI_SOCK_POST: {
		struct mini_sock_hdr_pyld __user *uhdr_pyld =
			(struct mini_sock_hdr_pyld __user *)arg;
		return mini_sock_ioctl_post(msock, uhdr_pyld);
	}
	case MINI_SOCK_COMPLETE: {
		struct mini_sock_hdr_pyld __user **uhdr_pyld_p =
			(struct mini_sock_hdr_pyld __user **)arg;
		return mini_sock_ioctl_complete(msock, uhdr_pyld_p);
	}
	default:
		return -EINVAL;
	}
}

static struct file_operations mini_sock_ops = {
	.owner = THIS_MODULE,
	.open = mini_sock_open,
	.release = mini_sock_release,
	.poll = mini_sock_poll,
	.unlocked_ioctl = mini_sock_ioctl,
};

static struct miscdevice mini_sock_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = KBUILD_MODNAME,
	.fops = &mini_sock_ops,
};

#if CONFIG_X86_64
static int __init mini_sock_irq_init(struct mini_sock_hdr_pyld *hdr_pyld)
{
	struct irq_alloc_info info;
	cpumask_var_t cpumask;
	unsigned int cpu;
	int irq;
	int r;

	if (mini_sock_irq >= 0)
		return request_irq(irq, mini_sock_irq_handler, 0,
				   KBUILD_MODNAME, NULL);

	if (!alloc_cpumask_var(&cpumask, GFP_KERNEL))
		return -ENOMEM;

	memset(&info, 0, sizeof(info));

	/* Use the current cpu for interrupt. */
	cpu = get_cpu();
	info.mask = cpumask_of(cpu);

	irq = irq_domain_alloc_irqs(x86_vector_domain, 1, cpu_to_node(cpu), &info);
	if (irq < 0) {
		r = irq;
		goto out;
	}

	irq_set_handler(irq, handle_edge_irq);

	/* no irq balancing as we use this cpu.  */
	 r = request_irq(irq, mini_sock_irq_handler, IRQF_NOBALANCING,
			 KBUILD_MODNAME, NULL);
	if (r)
		goto out;

	mini_sock_irq = irq;
	mini_sock_irq_cfg = irqd_cfg(irq_get_irq_data(irq));
	{
		struct msi_msg msg = {
			.arch_addr_lo = {
				.base_address = 0,
				.dest_mode_logical = 0,
				.destid_0_7 = mini_sock_irq_cfg->dest_apicid & 0xFF,
			},
			.arch_addr_hi = {
				.destid_8_31 = mini_sock_irq_cfg->dest_apicid >> 8,
			},
			.arch_data  = {
				.delivery_mode = 0,
				.vector = mini_sock_irq_cfg->vector,
			},
		};
		r = mini_sock_config(hdr_pyld, MINI_SOCK_CONFIG_MSI,
				     &msg, sizeof(msg), false);
		if (r) {
			free_irq(irq, NULL);
			irq_domain_free_irqs_common(x86_vector_domain, irq, 1);
		}
	}
out:
	put_cpu();
	free_cpumask_var(cpumask);
	return r;
}
#endif

static int __init mini_sock_init(void)
{
	u32 device_id;
	u32 vendor_id;
	u32 version;
	u32 magic;
	int r;

	if (!mmio_base) {
		pr_err("No MMIO base address is specified.\n");
		return -EINVAL;
	}

	mini_sock_virt = ioremap_driver_hardened(mmio_base, MINI_SOCK_MMIO_SIZE);
	if (!mini_sock_virt) {
		pr_err("Failed to ioremap mmio region 0x%lx+0x%x\n",
		       mmio_base, MINI_SOCK_MMIO_SIZE);
		return -ENOMEM;
	}

	magic = mini_sock_readl(MINI_SOCK_MMIO_MAGIC_VALUE);
	if (magic != MINI_SOCK_MAGIC) {
		pr_err("Unknown magic value 0x%x\n", magic);
		r = -ENODEV;
		goto err;
	}

	version = mini_sock_readl(MINI_SOCK_MMIO_VERSION);
	if (version != MINI_SOCK_VERSION) {
		pr_err("Unknown version number 0x%x\n", version);
		goto err;
	}

	device_id = mini_sock_readl(MINI_SOCK_MMIO_DEVICE_ID);
	if (device_id != MINI_SOCK_ID) {
		pr_err("Unknown device id 0x%x\n", device_id);
		goto err;
	}

	vendor_id = mini_sock_readl(MINI_SOCK_MMIO_VENDOR_ID);
	pr_info("Found mini-sock device magic 0x%x version 0x%x device_id 0x%x vendor_id 0x%x\n",
		magic, version, device_id, vendor_id);

	mutex_lock(&mutex_lock);
	r = misc_register(&mini_sock_dev);
	if (r) {
		pr_err("failed to register misc device.\n");
		goto err;
	}

	dma_set_coherent_mask(mini_sock_dev.this_device, DMA_BIT_MASK(64));
	mini_sock_hdr_pyld = dma_alloc_coherent(mini_sock_dev.this_device,
						PAGE_SIZE, &mini_sock_dma_addr,
						GFP_KERNEL);
	if (!mini_sock_hdr_pyld) {
		r = -ENOMEM;
		goto err_dma_free;
	}

	r = mini_sock_config(mini_sock_hdr_pyld, MINI_SOCK_CONFIG_CID,
			     &guest_cid, sizeof(guest_cid), true);
	if (r)
		goto err_dma_free;
	r = mini_sock_config(mini_sock_hdr_pyld, MINI_SOCK_CONFIG_MTU,
			     &mini_sock_mtu, sizeof(mini_sock_mtu), true);
	if (r)
		goto err_dma_free;
	mini_sock_mtu = min(mini_sock_mtu, MINI_SOCK_MTU_MAX);

	mini_sock_reset_device();

#if CONFIG_X86_64
	r = mini_sock_irq_init(mini_sock_hdr_pyld);
#else
	if (mini_sock_irq >= 0) {
		r = request_irq(irq, mini_sock_irq_handler, 0,
				KBUILD_MODNAME, NULL);
	}
#endif
	if (r)
		goto err_dma_free;

	pr_info("Initialized mini sock device.\n");
	mutex_unlock(&mutex_lock);
	return 0;

err_dma_free:
	dma_free_coherent(mini_sock_dev.this_device, PAGE_SIZE,
			  mini_sock_hdr_pyld, mini_sock_dma_addr);
	misc_deregister(&mini_sock_dev);
	mutex_unlock(&mutex_lock);
err:
	iounmap(mini_sock_virt);
	pr_err("Failed to initialize mini sock device.\n");
	return r;
}
module_init(mini_sock_init);

static void mini_sock_exit(void)
{
	mutex_lock(&mutex_lock);
	if (mini_sock_hdr_pyld) {
		mini_sock_reset_device();
		dma_free_coherent(mini_sock_dev.this_device, PAGE_SIZE,
				  mini_sock_hdr_pyld, mini_sock_dma_addr);
	}
	misc_deregister(&mini_sock_dev);
	if (mini_sock_irq > 0) {
		free_irq(mini_sock_irq, NULL);
#if CONFIG_X86_64
		irq_domain_free_irqs_common(x86_vector_domain, mini_sock_irq, 1);
#endif
	}

	iounmap(mini_sock_virt);
}
module_exit(mini_sock_exit);

MODULE_AUTHOR("Isaku Yamahata <isaku.yamahata@gmail.com>");
MODULE_DESCRIPTION("Mini Sock guest driver");
MODULE_LICENSE("GPL");
