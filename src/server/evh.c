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

struct Evh {
	i32 fd;
	u16 port;
	u8 buffer[EVH_PACKET_SIZE];
	struct sockaddr_in src_addr;
	u32 complete;
	Async *async;
	struct msghdr message;
	struct iovec vec[1];
	struct io_uring_sqe proc_next_msg[1];
	AsyncCallback callback;
	void *ctx;
	bool next_message_called;
};

STATIC i32 evh_next_message(Evh *evh) {
	return async_schedule(evh->async, evh->proc_next_msg, 1);
}

STATIC void evh_callback(i32 res, u64 user_data, void *ctx) {
	Evh *evh = ctx;
	evh->callback(res, user_data, evh);
	if (user_data == U64_MAX) {
		if (evh_next_message(evh) < 0) async_stop(evh->async);
	}
}

STATIC void evh_on_start_loop(void *ctx) {
	Evh *evh = ctx;
	evh->next_message_called = false;
}

const u8 *evh_get_packet(Evh *evh) { return evh->buffer; }

const struct sockaddr_in *evh_get_src_addr(Evh *evh) { return &evh->src_addr; }

i32 evh_init(Evh **evh, EvhConfig *config) {
	struct sockaddr_in addr = {.sin_family = AF_INET,
				   .sin_port = htons(config->port),
				   .sin_addr = {htonl(config->addr)}};
	Evh *ret;
	i32 res;
	u64 one = 1;
	u64 addrlen = sizeof(addr);

	if (config->queue_depth < 2) {
		errno = EINVAL;
		return -1;
	}

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
	ret->port = ntohs(addr.sin_port);

	if (async_init(&ret->async, config->queue_depth, evh_callback,
		       evh_on_start_loop, ret) < 0) {
		evh_destroy(ret);
		return -1;
	}

	i32 ring_fd = async_ring_fd(ret->async);
	if (io_uring_register(ring_fd, IORING_REGISTER_FILES, (i32[]){ret->fd},
			      1) < 0) {
		evh_destroy(ret);
		return -1;
	}

	ret->vec[0].iov_base = ret->buffer;
	ret->vec[0].iov_len = EVH_PACKET_SIZE;
	ret->message.msg_name = &ret->src_addr;
	ret->message.msg_namelen = sizeof(ret->src_addr);
	ret->message.msg_iov = ret->vec;
	ret->message.msg_iovlen = 1;

	ret->proc_next_msg[0].opcode = IORING_OP_RECVMSG;
	ret->proc_next_msg[0].fd = 0;
	ret->proc_next_msg[0].flags = IOSQE_FIXED_FILE,
	ret->proc_next_msg[0].addr = (u64)&ret->message;
	ret->proc_next_msg[0].len = sizeof(ret->message);
	ret->proc_next_msg[0].user_data = U64_MAX;

	ret->callback = config->callback;

	*evh = ret;
	return 0;
}

i32 evh_schedule(Evh *evh, const struct io_uring_sqe *events, u32 count) {
	if (!evh->next_message_called) {
		evh->next_message_called = true;
		((struct io_uring_sqe *)events)[count++] =
		    evh->proc_next_msg[0];
	}
	return async_schedule(evh->async, events, count);
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

