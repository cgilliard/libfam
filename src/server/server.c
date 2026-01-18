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
#include <libfam/atomic.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/server.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>

#define MAX_PACKET_SIZE 1400

struct Server {
	i32 fd;
	u16 port;
	Async *async;
	u8 packet_buffer[MAX_PACKET_SIZE];
	u32 stop;
};

STATIC void server_on_complete(i32 res, u64 user_data, void *ctx) {
	u8 buffer[MAX_PACKET_SIZE + 1] = {0};
	Server *server = ctx;
	if (user_data == U64_MAX) return;

	if (res < 0) {
		println("err!");
		return;
	}
	fastmemcpy(buffer, server->packet_buffer, res);
	println("on complete {} {} {} {} data='{}'", server->fd, user_data, res,
		getpid(), buffer);

	struct io_uring_sqe sqe = {.opcode = IORING_OP_READ,
				   .addr = (u64)server->packet_buffer,
				   .fd = server->fd,
				   .len = MAX_PACKET_SIZE,
				   .off = 0,
				   .user_data = user_data + 1};

	async_execute_only(server->async, (struct io_uring_sqe[]){sqe}, 1);
}

u16 server_port(Server *server) { return server->port; }

i32 server_init(Server **server, ServerConfig *config) {
	struct sockaddr_in addr = {.sin_family = AF_INET,
				   .sin_port = htons(config->port),
				   .sin_addr = {htonl(INADDR_ANY)}};
	i32 res;
	u64 one = 1;
	u64 addrlen = sizeof(addr);
	Server *ret = smap(sizeof(Server));
	if (!ret) return -1;
	ret->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ret->fd < 0) {
		server_destroy(ret);
		return -1;
	}
	res = setsockopt(ret->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (res < 0) {
		server_destroy(ret);
		return -1;
	}
	if (bind(ret->fd, (void *)&addr, addrlen) < 0) {
		server_destroy(ret);
		return -1;
	}
	if (getsockname(ret->fd, (void *)&addr, &addrlen) < 0) {
		server_destroy(ret);
		return -1;
	}
	ret->port = ntohs(addr.sin_port);

	if (async_init(&ret->async, config->async_queue_depth,
		       server_on_complete, ret) < 0) {
		server_destroy(ret);
		return -1;
	}

	*server = ret;
	return 0;
}

i32 server_start(Server *server) {
	struct io_uring_sqe sqe = {.opcode = IORING_OP_READ,
				   .addr = (u64)server->packet_buffer,
				   .fd = server->fd,
				   .len = MAX_PACKET_SIZE,
				   .off = 0,
				   .user_data = 1};

	while (!__aload32(&server->stop))
		if (async_execute(server->async, (struct io_uring_sqe[]){sqe},
				  1, true) < 0)
			return -1;
	__astore32(&server->stop, 0);
	return 0;
}

i32 server_stop(Server *server) {
	__astore32(&server->stop, 1);
	struct io_uring_sqe sqe = {.opcode = IORING_OP_NOP,
				   .user_data = U64_MAX};
	if (async_execute_only(server->async, (struct io_uring_sqe[]){sqe}, 1) <
	    0)
		return -1;
	while (__aload32(&server->stop));
	return 0;
}

void server_destroy(Server *server) {
	if (!server) return;
	if (server->fd > 0) close(server->fd);
	server->fd = -1;
	if (server->async) async_destroy(server->async);
	server->async = NULL;
	munmap(server, sizeof(Server));
}

