/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025-2026 Christopher Gilliard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *******************************************************************************/

#include <libfam/async.h>
#include <libfam/evh.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>

#define MAX_PACKET_SIZE 1400

struct Evh {
	i32 fd;
	u16 port;
	u8 buffer[MAX_PACKET_SIZE];
	struct sockaddr_in src_addr;
	u32 complete;
	Async *async;
	struct msghdr message;
	struct iovec vec[1];
	struct io_uring_sqe proc_next_msg[1];
};

STATIC i32 evh_next_message(Evh *evh) {
	return async_schedule(evh->async, evh->proc_next_msg, 1);
}

STATIC void evh_callback(i32 res, u64 user_data, void *ctx) {
	Evh *evh = ctx;

	if (res >= 0 && res < MAX_PACKET_SIZE) {
		u8 msg[MAX_PACKET_SIZE + 1] = {0};
		fastmemcpy(msg, evh->buffer, res);
		println("res={},user_data={},buf={},msg[0]={},evh->fd={}", res,
			user_data, msg, msg[0], evh->fd);
	}

	if (evh_next_message(evh) < 0) async_stop(evh->async);
}

i32 evh_init(Evh **evh, EvhConfig *config) {
	struct sockaddr_in addr = {.sin_family = AF_INET,
				   .sin_port = htons(config->port),
				   .sin_addr = {htonl(config->addr)}};
	Evh *ret;
	i32 res;
	u64 one = 1;
	u64 addrlen = sizeof(addr);

	ret = smap(sizeof(Evh));
	if (!ret) return -1;

	ret->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ret->fd < 0) {
		evh_destroy(ret);
		return -1;
	}
	res = setsockopt(ret->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (res < 0) {
		evh_destroy(ret);
		return -1;
	}
	if (bind(ret->fd, (void *)&addr, addrlen) < 0) {
		evh_destroy(ret);
		return -1;
	}
	if (getsockname(ret->fd, (void *)&addr, &addrlen) < 0) {
		evh_destroy(ret);
		return -1;
	}
	println("fd={}, addr.sin_port={}", ret->fd, addr.sin_port);
	ret->port = ntohs(addr.sin_port);

	if (async_init(&ret->async, config->queue_depth, evh_callback, ret) <
	    0) {
		evh_destroy(ret);
		return -1;
	}

	i32 ring_fd = async_ring_fd(ret->async);
	struct iovec iov = {.iov_base = ret->buffer,
			    .iov_len = MAX_PACKET_SIZE};

	if (io_uring_register(ring_fd, IORING_REGISTER_BUFFERS, &iov, 1) < 0) {
		evh_destroy(ret);
		return -1;
	}

	ret->vec[0].iov_base = ret->buffer;
	ret->vec[0].iov_len = MAX_PACKET_SIZE;
	ret->message.msg_name = &ret->src_addr;
	ret->message.msg_namelen = sizeof(ret->src_addr);
	ret->message.msg_iov = ret->vec;
	ret->message.msg_iovlen = 1;

	ret->proc_next_msg[0].opcode = IORING_OP_RECVMSG;
	ret->proc_next_msg[0].fd = ret->fd;
	ret->proc_next_msg[0].addr = (u64)&ret->message;
	ret->proc_next_msg[0].len = sizeof(ret->message);
	ret->proc_next_msg[0].user_data = U64_MAX;

	*evh = ret;
	return 0;
}

i32 evh_start(Evh *evh) {
	if (evh_next_message(evh) < 0) return -1;
	return async_process(evh->async);
}

i32 evh_stop(Evh *evh) { return async_stop(evh->async); }

void evh_destroy(Evh *evh) {
	if (!evh) return;
	if (evh->async) async_destroy(evh->async);
	evh->async = NULL;
	if (evh->fd > 0) close(evh->fd);
	munmap(evh, sizeof(Evh));
}
u16 evh_port(Evh *evh) { return evh->port; }

