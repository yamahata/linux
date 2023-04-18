/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * sample test program for mini sock device
 *
 * Copyright (c) 2023 Intel Corporation
 *
 * Author:
 *  Isaku Yamahata <isaku.yamahata@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>

#include <assert.h>
#include <limits.h>
#include <err.h>
#include <getopt.h>

#include <asm/byteorder.h>

#include "../../../include/uapi/linux/mini_sock.h"

#define DEVICE_PATH	"/dev/mini_sock"

static uint64_t mtu;
static uint64_t cid;

static uint16_t sock_type = MINI_SOCK_TYPE_DGRAM;

static uint64_t my_cid = MINI_SOCK_CID_ANY;
static uint64_t peer_cid = MINI_SOCK_CID_ANY;
static uint32_t my_port = MINI_SOCK_PORT_ANY;
static uint32_t peer_port = MINI_SOCK_PORT_ANY;

static void mini_sock_print_ret_state(const struct mini_sock_hdr *hdr)
{
	int32_t ret = __le32_to_cpu(hdr->ret);
	printf("hdr ret 0x%"PRIx32" state 0x%"PRIx32"\n",
	       ret, __le32_to_cpu(hdr->state));
	if (ret < 0)
		printf("errno: %d %s\n", -ret, strerror(-ret));
}

static int mini_sock_complete(int fd, struct mini_sock_hdr_pyld **hdr_pyld_p)
{
	int r;
	struct mini_sock_hdr *hdr;

	r = ioctl(fd, MINI_SOCK_COMPLETE, hdr_pyld_p);
	if (r < 0)
		err(EXIT_FAILURE, "ioctl complete failed. %p\n", *hdr_pyld_p);
	hdr = &(*hdr_pyld_p)->hdr;
	mini_sock_print_ret_state(hdr);
	assert(hdr->ret == __cpu_to_le32(MINI_SOCK_SUCCESS));
	assert(hdr->state == __cpu_to_le32(MINI_SOCK_STATE_SUCCESS));
	return r;
}

#if 0
static struct mini_sock_hdr_pyld *mini_sock_complete_any(int fd)
{
	struct mini_sock_hdr_pyld *hdr_pyld = MINI_SOCK_COMPLETE_ANY;
	struct mini_sock_hdr_pyld **hdr_pyld_p = &hdr_pyld;
	mini_sock_complete(fd, hdr_pyld_p);
	return *hdr_pyld_p;
}
#endif

static int __mini_sock_post(int fd, struct mini_sock_hdr_pyld *hdr_pyld)
{
	const struct mini_sock_hdr *hdr = &hdr_pyld->hdr;
	int r;

	printf("hdr %p src_cid 0x%llx dst_cid 0x%llx "
	       "src port 0x%"PRIx32" dst port 0x%"PRIx32" "
	       "len 0x%"PRIx32" type 0x%"PRIx16" "
	       "op 0x%"PRIx16" flags 0x%"PRIx32"\n",
	       hdr,
	       __le64_to_cpu(hdr->src_cid), __le64_to_cpu(hdr->dst_cid),
	       __le32_to_cpu(hdr->src_port), __le32_to_cpu(hdr->dst_port),
	       __le32_to_cpu(hdr->len), __le16_to_cpu(hdr->type),
	       __le16_to_cpu(hdr->op), __le32_to_cpu(hdr->flags));
	assert(__le32_to_cpu(hdr->ret) == MINI_SOCK_SUCCESS);
	assert(__le32_to_cpu(hdr->state) == MINI_SOCK_STATE_ONREQUEST);
	r = ioctl(fd, MINI_SOCK_POST, hdr_pyld);
	if (r < 0)
		err(EXIT_FAILURE, "ioctl post failed.\n");
	mini_sock_print_ret_state(hdr);
	assert(__le32_to_cpu(hdr->state) == MINI_SOCK_STATE_SUCCESS ||
	       __le32_to_cpu(hdr->state) == MINI_SOCK_STATE_ERROR ||
	       __le32_to_cpu(hdr->state) == MINI_SOCK_STATE_INFLIGHT);
	switch (__le32_to_cpu(hdr->state)) {
	case MINI_SOCK_STATE_SUCCESS:
		assert(__le32_to_cpu(hdr->ret) == MINI_SOCK_SUCCESS ||
		       __le32_to_cpu(hdr->ret) == MINI_SOCK_SUCCESS_DONE);
		break;
	case MINI_SOCK_STATE_ERROR:
		assert(__le32_to_cpu(hdr->ret) < 0);
		break;
	case MINI_SOCK_STATE_INFLIGHT:
		assert(__le32_to_cpu(hdr->ret) == MINI_SOCK_SUCCESS);
		break;
	case MINI_SOCK_STATE_ONREQUEST:
	default:
		abort();
	}
	return r;
}

static int mini_sock_post_imm(int fd, struct mini_sock_hdr_pyld *hdr_pyld)
{
	int r;
	struct mini_sock_hdr *hdr;

	r = __mini_sock_post(fd, hdr_pyld);
	hdr = &hdr_pyld->hdr;
	assert(hdr->ret == __cpu_to_le32(MINI_SOCK_SUCCESS_DONE));
	assert(hdr->state == __cpu_to_le32(MINI_SOCK_STATE_SUCCESS));
	return r;
}

static int mini_sock_post(int fd, struct mini_sock_hdr_pyld *hdr_pyld)
{
	int r;

	r = __mini_sock_post(fd, hdr_pyld);
	assert(hdr_pyld->hdr.ret == __cpu_to_le32(MINI_SOCK_SUCCESS) ||
	       hdr_pyld->hdr.ret == __cpu_to_le32(MINI_SOCK_SUCCESS_DONE));
	return r;
}

static int mini_sock_post_wait(int fd, struct mini_sock_hdr_pyld *hdr_pyld)
{
	int r;

	r = mini_sock_post(fd, hdr_pyld);
	if (hdr_pyld->hdr.ret == __cpu_to_le32(MINI_SOCK_SUCCESS_DONE)) {
		assert(hdr_pyld->hdr.state == __cpu_to_le32(MINI_SOCK_STATE_SUCCESS));
		return r;
	}
	return mini_sock_complete(fd, &hdr_pyld);
}

static uint64_t mini_sock_getsockopt(int fd, uint64_t key)
{
	struct mini_sock_config_data *config;
	uint64_t value;
	union {
		struct mini_sock_hdr_pyld hdr_pyld;
		uint8_t data[sizeof(struct mini_sock_hdr) +
			     sizeof(*config) + sizeof(value)];
	} u;

	u.hdr_pyld.hdr = (struct mini_sock_hdr) {
		.src_cid = __cpu_to_le64(MINI_SOCK_CID_ANY),
		.dst_cid = __cpu_to_le64(MINI_SOCK_CID_ANY),
		.src_port = __cpu_to_le32(MINI_SOCK_PORT_ANY),
		.dst_port = __cpu_to_le32(MINI_SOCK_PORT_ANY),
		.len = __cpu_to_le32(sizeof(*config) + sizeof(value)),
		.type = __cpu_to_le16(sock_type),
		.op = __cpu_to_le16(MINI_SOCK_OP_CONFIG),
		.flags = __cpu_to_le32(MINI_SOCK_CONFIG_GET),
		.ret = __cpu_to_le32(MINI_SOCK_SUCCESS),
		.state = __cpu_to_le32(MINI_SOCK_STATE_ONREQUEST),
	};
	config = (struct mini_sock_config_data *)u.hdr_pyld.payload;
	*config = (struct mini_sock_config_data) {
		.key = __cpu_to_le64(key),
	};

	mini_sock_post_imm(fd, &u.hdr_pyld);
	return __le64_to_cpu(*((uint64_t*)config->data));
}

/*
 * For client: bind() + connect()
 * For server: bind() + listen()
 */
static void __mini_sock_bind(int fd,
			     uint64_t src_cid, uint64_t dst_cid,
			     uint32_t src_port, uint32_t dst_port)
{
	struct mini_sock_hdr_pyld hdr_pyld = {
		.hdr = {
			.src_cid = __cpu_to_le64(src_cid),
			.dst_cid = __cpu_to_le64(dst_cid),
			.src_port = __cpu_to_le32(src_port),
			.dst_port = __cpu_to_le32(dst_port),
			.len = __cpu_to_le32(0),
			.type = __cpu_to_le16(sock_type),
			.op = __cpu_to_le16(MINI_SOCK_OP_REQUEST),
			.flags = __cpu_to_le32(0),
			.ret = __cpu_to_le32(MINI_SOCK_SUCCESS),
			.state = __cpu_to_le32(MINI_SOCK_STATE_ONREQUEST),
		},
	};
	mini_sock_post_imm(fd, &hdr_pyld);

	my_port = __le32_to_cpu(hdr_pyld.hdr.src_port);
	printf("myport 0x%"PRIx32"\n", my_port);
}

static void mini_sock_connect(int fd,
			      uint64_t src_cid, uint64_t dst_cid,
			      uint32_t src_port, uint32_t dst_port)
{
	__mini_sock_bind(fd, src_cid, dst_cid, src_port, dst_port);
}

static void mini_sock_listen(int fd,
			     uint64_t src_cid, uint64_t dst_cid,
			     uint32_t src_port, uint32_t dst_port)
{
	__mini_sock_bind(fd, src_cid, dst_cid, src_port, dst_port);
}

static void mini_sock_accept(int fd,
			     uint64_t src_cid, uint64_t *dst_cid,
			     uint32_t src_port, uint32_t *dst_port,
			     int *new_fd)
{
	int r;

	struct mini_sock_hdr_pyld hdr_pyld = {
		.hdr = {
			.src_cid = __cpu_to_le64(src_cid),
			.dst_cid = __cpu_to_le64(MINI_SOCK_CID_ANY),
			.src_port = __cpu_to_le32(src_port),
			.dst_port = __cpu_to_le32(MINI_SOCK_PORT_ANY),
			.len = __cpu_to_le32(0),
			.type = __cpu_to_le16(sock_type),
			.op = __cpu_to_le16(MINI_SOCK_OP_RESPONSE),
			.flags = __cpu_to_le32(0),
			.ret = __cpu_to_le32(MINI_SOCK_SUCCESS),
			.state = __cpu_to_le32(MINI_SOCK_STATE_ONREQUEST),
		},
	};
	r = mini_sock_post_wait(fd, &hdr_pyld);

	*dst_cid = __le64_to_cpu(hdr_pyld.hdr.dst_cid);
	*dst_port = __le32_to_cpu(hdr_pyld.hdr.dst_port);
	*new_fd = r;
	printf("fd %d dst_cid 0x%"PRIx64" dst_port 0x%"PRIx32" new_fd %d\n",
	       fd, *dst_cid, *dst_port, *new_fd);
}

static void mini_sock_shutdown(int fd,
			       uint64_t src_cid, uint64_t dst_cid,
			       uint32_t src_port, uint32_t dst_port)
{
	struct mini_sock_hdr_pyld hdr_pyld = {
		.hdr = {
			.src_cid = __cpu_to_le64(src_cid),
			.dst_cid = __cpu_to_le64(dst_cid),
			.src_port = __cpu_to_le32(src_port),
			.dst_port = __cpu_to_le32(dst_port),
			.len = __cpu_to_le32(0),
			.type = __cpu_to_le16(sock_type),
			.op = __cpu_to_le16(MINI_SOCK_OP_SHUTDOWN),
			.flags = __cpu_to_le32(0),
			.ret = __cpu_to_le32(MINI_SOCK_SUCCESS),
			.state = __cpu_to_le32(MINI_SOCK_STATE_ONREQUEST),
		},
	};
	mini_sock_post(fd, &hdr_pyld);
}

static void mini_sock_send(int fd, uint64_t src_cid, uint64_t dst_cid,
			   uint32_t src_port, uint32_t dst_port,
			   struct mini_sock_hdr_pyld *hdr_pyld,
			   uint32_t len)
{
	hdr_pyld->hdr = (struct mini_sock_hdr) {
		.src_cid = __cpu_to_le64(src_cid),
		.dst_cid = __cpu_to_le64(dst_cid),
		.src_port = __cpu_to_le32(src_port),
		.dst_port = __cpu_to_le32(dst_port),
		.len = __cpu_to_le32(len),
		.type = __cpu_to_le16(sock_type),
		.op = __cpu_to_le16(MINI_SOCK_OP_RW),
		.flags = __cpu_to_le32(MINI_SOCK_RW_SEND),
		.ret = __cpu_to_le32(MINI_SOCK_SUCCESS),
		.state = __cpu_to_le32(MINI_SOCK_STATE_ONREQUEST),
	};
	mini_sock_post_wait(fd, hdr_pyld);
}

static void mini_sock_recv(int fd, uint64_t src_cid, uint64_t dst_cid,
			   uint32_t src_port, uint32_t dst_port,
			   struct mini_sock_hdr_pyld *hdr_pyld,
			   uint32_t len)
{
	hdr_pyld->hdr = (struct mini_sock_hdr) {
		.src_cid = __cpu_to_le64(src_cid),
		.dst_cid = __cpu_to_le64(dst_cid),
		.src_port = __cpu_to_le32(src_port),
		.dst_port = __cpu_to_le32(dst_port),
		.len = __cpu_to_le32(len),
		.type = __cpu_to_le16(sock_type),
		.op = __cpu_to_le16(MINI_SOCK_OP_RW),
		.flags = __cpu_to_le32(MINI_SOCK_RW_RECV),
		.ret = __cpu_to_le32(MINI_SOCK_SUCCESS),
		.state = __cpu_to_le32(MINI_SOCK_STATE_ONREQUEST),
	};
	mini_sock_post_wait(fd, hdr_pyld);
}

static void dgram_server(int fd)
{
	int count = 0;
	struct mini_sock_hdr_pyld *hdr_pyld = malloc(mtu);
	assert(hdr_pyld);

	while (true) {
		memset(hdr_pyld, 0, mtu);
		mini_sock_recv(fd, peer_cid, my_cid, peer_port, my_port,
			       hdr_pyld, mtu - sizeof(hdr_pyld->hdr));

		struct mini_sock_hdr *hdr = &hdr_pyld->hdr;
		((char *)hdr_pyld)[mtu - 1] = '\0';
		printf("Recived from client "
		       "src cid 0x%llx dst cid 0x%llx "
		       "src port 0x%"PRIx32" dst port 0%"PRIx32" "
		       "len 0x%"PRIx32" \"%s\"\n",
		       __le64_to_cpu(hdr->src_cid),
		       __le64_to_cpu(hdr->dst_cid),
		       __le32_to_cpu(hdr->src_port),
		       __le32_to_cpu(hdr->dst_port),
		       __le32_to_cpu(hdr->len),
		       hdr_pyld->payload);

		uint64_t client_cid = __le64_to_cpu(hdr->src_cid);
		uint32_t client_port = __le32_to_cpu(hdr->src_port);
		memset(hdr_pyld, 0, mtu);

		uint32_t len;
		len = snprintf((char *)hdr_pyld->payload,
			       mtu - sizeof(hdr_pyld->hdr),
			       "Reply from dgram server "
			       "src cid 0x%"PRIx64" dst cid 0x%"PRIx64" "
			       "src port 0x%"PRIx32" dst port 0x%"PRIx32" "
			       "pid %d count %d",
			       my_cid, client_cid, my_port, client_port,
			       getpid(), count);
		assert(len > 0);
		len++;
		mini_sock_send(fd, my_cid, client_cid, my_port, client_port,
			       hdr_pyld, len);

		mini_sock_shutdown(fd, my_cid, client_cid, my_port, client_port);

		count++;
	}
}

static void stream_worker(int cfd, uint64_t client_cid, uint32_t client_port,
			  int server_count)
{
#define STREAM_COUNT_MAX	10
	int count = 0;
	struct mini_sock_hdr_pyld *hdr_pyld = malloc(mtu);
	assert(hdr_pyld);

	for (count = 0; count < STREAM_COUNT_MAX; count++) {
		memset(hdr_pyld, 0, mtu);
		mini_sock_recv(cfd, client_cid, my_cid, client_port, my_port,
			       hdr_pyld, mtu - sizeof(hdr_pyld->hdr));

		struct mini_sock_hdr *hdr = &hdr_pyld->hdr;
		((char *)hdr_pyld)[mtu - 1] = '\0';
		printf("Recived from client "
		       "src cid 0x%llx dst cid 0x%llx "
		       "src port 0x%"PRIx32" dst port 0%"PRIx32" "
		       "len 0x%"PRIx32" \"%s\"\n",
		       __le64_to_cpu(hdr->src_cid),
		       __le64_to_cpu(hdr->dst_cid),
		       __le32_to_cpu(hdr->src_port),
		       __le32_to_cpu(hdr->dst_port),
		       __le32_to_cpu(hdr->len),
		       hdr_pyld->payload);

		assert(client_cid == __le64_to_cpu(hdr->src_cid));
		assert(client_port == __le32_to_cpu(hdr->src_port));
		memset(hdr_pyld, 0, mtu);

		uint32_t len;
		len = snprintf((char *)hdr_pyld->payload,
			       mtu - sizeof(hdr_pyld->hdr),
			       "Reply from stream server "
			       "src cid 0x%"PRIx64" dst cid 0x%"PRIx64" "
			       "src port 0x%"PRIx32" dst port 0x%"PRIx32" "
			       "pid %d server_count %d count %d",
			       my_cid, client_cid, my_port, client_port,
			       getpid(), server_count, count);
		assert(len > 0);
		len++;

		mini_sock_send(cfd, my_cid, client_cid, my_port, client_port,
			       hdr_pyld, len);
	}

	mini_sock_shutdown(cfd, my_cid, client_cid,
			   my_port, client_port);
	free(hdr_pyld);
}

static void stream_server(int fd)
{
	int count = 0;

	while (true) {
		uint64_t client_cid;
		uint32_t client_port;
		int cfd;

		mini_sock_accept(fd, my_cid, &client_cid, my_port,
				 &client_port, &cfd);
		stream_worker(cfd, client_cid, client_port, count);
		close(cfd);
		count++;
	}
}

static void client(int fd)
{
	int count = 0;
	struct mini_sock_hdr_pyld *hdr_pyld;

	hdr_pyld = malloc(mtu);
	assert(hdr_pyld);
	while (true) {
		uint32_t len;

		memset(hdr_pyld, 0, mtu);
		len = snprintf((char *)hdr_pyld->payload,
			       mtu - sizeof(hdr_pyld->hdr),
			       "Hello from client "
			       "src cid 0x%"PRIx64" dst cid 0x%"PRIx64" "
			       "src port 0x%"PRIx32" dst port 0x%"PRIx32" "
			       "pid %d count %d",
			       my_cid, peer_cid, my_port, peer_port,
			       getpid(), count++);
		assert(len > 0);
		len++;	/* terminating NULL */
		mini_sock_send(fd, my_cid, peer_cid, my_port, peer_port,
			       hdr_pyld, len);

		memset(hdr_pyld, 0, mtu);
		mini_sock_recv(fd, peer_cid, my_cid, peer_port, my_port,
			       hdr_pyld, mtu - sizeof(hdr_pyld->hdr));

		((char *)hdr_pyld)[mtu - 1] = '\0';
		struct mini_sock_hdr *hdr = &hdr_pyld->hdr;
		printf("recived from server "
		       "src cid 0x%llx dst cid 0x%llx "
		       "src port 0x%x dst port 0x%x len %d "
		       "\"%s\"\n",
		       __le64_to_cpu(hdr->src_cid), __le64_to_cpu(hdr->dst_cid),
		       __le32_to_cpu(hdr->src_port), __le32_to_cpu(hdr->dst_port),
		       __le16_to_cpu(hdr->len), hdr_pyld->payload);
	}
}

static void usage(const char *prog)
{
	printf("Usage: %s --server-cid=<cid> --server-port=<port> [--client-port=<port>]\n"
	       "Options:\n"
	       "--help, -h: print this help\n"
	       "--device <device>, -d <device>: device file to use. default \"" DEVICE_PATH "\"\n"
	       "--server-cid <cid>, -c <cid>: server cid\n"
	       "--server-port <port>, -p <port>: server port\n"
	       "--client-port <port>, -P <port>: client port\n"
	       "--client, -C: client mode\n"
	       "--server, -s: server mode\n"
	       "--datagram, -D: datagram mode\n"
	       "--stream, -S: stream mode\n",
	       prog);
}

int main(int argc, char **argv)
{
	char *dev = DEVICE_PATH;
	bool do_server = false;
	const struct option options[] = {
		{ "device", required_argument, NULL, 'd' },

		{ "server-cid", required_argument, NULL, 'c'},
		{ "server-port", required_argument, NULL, 'p'},
		{ "client-port", required_argument, NULL, 'P'},

		{ "client", no_argument, NULL, 'C' },
		{ "server", no_argument, NULL, 's' },

		{ "datagram", no_argument, NULL, 'D' },
		{ "stream", no_argument, NULL, 'S' },

		{ "help", no_argument, NULL, 'h' },
	};

	uint64_t server_cid = MINI_SOCK_CID_ANY;
	uint32_t server_port = MINI_SOCK_PORT_ANY;
	uint32_t client_port = MINI_SOCK_PORT_ANY;

	int c;
	while ((c = getopt_long(argc, argv, "d:c:p:P:CsDSh", options,
				NULL)) != -1) {
		switch (c) {
		case 'd':
			dev = optarg;
			break;

		case 'c':
			server_cid = strtol(optarg, NULL, 0);
			break;
		case 'p':
			server_port = strtol(optarg, NULL, 0);
			break;
		case 'P':
			client_port = strtol(optarg, NULL, 0);
			break;

		case 'C':
			do_server = false;
			break;
		case 's':
			do_server = true;
			break;

		case 'D':
			sock_type = MINI_SOCK_TYPE_DGRAM;
			break;
		case 'S':
			sock_type = MINI_SOCK_TYPE_STREAM;
			break;
		case 'h':
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	int fd = open(dev, O_RDWR);
	if (fd < 0)
		err(EXIT_FAILURE, "failed to open %s", dev);

	cid = mini_sock_getsockopt(fd, MINI_SOCK_CONFIG_CID);
	mtu = mini_sock_getsockopt(fd, MINI_SOCK_CONFIG_MTU);
	printf("cid 0x%"PRIx64" mtu 0x%"PRIx64"\n", cid, mtu);

	if (do_server) {
		my_cid = cid;
		my_port = server_port;
		mini_sock_listen(fd, my_cid, peer_cid, my_port, peer_port);
	} else {
		my_cid = cid;
		my_port = client_port;
		peer_cid = server_cid;
		peer_port = server_port;
		mini_sock_connect(fd, my_cid, peer_cid, my_port, peer_port);
	}
	printf("my_cid 0x%"PRIx64" peer_cid 0x%"PRIx64" "
	       "my_port 0x%"PRIx32" peer_port 0x%"PRIx32"\n",
	       my_cid, peer_cid, my_port, peer_port);

	if (do_server) {
		if (sock_type == MINI_SOCK_TYPE_DGRAM)
			dgram_server(fd);
		else
			stream_server(fd);
	} else
		client(fd);

	return EXIT_SUCCESS;
}
