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

#include <libfam/atomic.h>
#include <libfam/bptree.h>
#include <libfam/db.h>
#include <libfam/evh.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/server.h>
#include <libfam/test.h>

typedef struct {
	u64 msgs;
	u64 non_packet;
} EvhTestState;

EvhTestState *recv_msgs = NULL;

void test_evh_callback(i32 res, u64 user_data, void *ctx) {
	Evh *evh = ctx;
	if (user_data == U64_MAX && res > 0 && res <= EVH_PACKET_SIZE) {
		u8 buf[EVH_PACKET_SIZE + 1] = {0};
		const struct sockaddr_in *src_addr = evh_get_src_addr(evh);
		u32 addr = htonl(src_addr->sin_addr.s_addr);
		fastmemcpy(buf, evh_get_packet(evh), res);
		ASSERT_EQ(addr, 0x7F000001, "in addr localhost");
		struct io_uring_sqe sqe = {.opcode = IORING_OP_NOP,
					   .user_data = 123};
		evh_schedule(evh, (struct io_uring_sqe[2]){sqe}, 1);
	} else {
		__aadd64(&recv_msgs->non_packet, 1);
	}
	__aadd64(&recv_msgs->msgs, 1);
}

Test(evh) {
	i32 res;
	struct sockaddr_in dest_addr = {.sin_family = AF_INET,
					.sin_addr = {htonl(0x7f000001U)}};
	struct iovec msgvec[1] = {
	    {.iov_base = "Hello1", .iov_len = 6},
	};
	struct msghdr msg = {.msg_name = &dest_addr,
			     .msg_namelen = sizeof(dest_addr),
			     .msg_iov = msgvec,
			     .msg_iovlen = 1};
	Evh *evh = NULL;
	EvhConfig config = {.queue_depth = 16, .callback = test_evh_callback};

	recv_msgs = smap(sizeof(EvhTestState));

	res = evh_init(&evh, &config);
	ASSERT(!res, "evh_init");

	i32 pid = fork();
	ASSERT(pid >= 0, "pid");
	if (!pid) {
		evh_start(evh);
		exit_group(0);
	}

	i32 cfd = socket(AF_INET, SOCK_DGRAM, 0);
	ASSERT(cfd > 0, "socket");
	dest_addr.sin_port = htons(evh_port(evh));

	res = sendmsg(cfd, &msg, 0);
	ASSERT_EQ(res, 6, "sendmsg");
	msgvec[0].iov_base = "abcdef";
	res = sendmsg(cfd, &msg, 0);
	ASSERT_EQ(res, 6, "sendmsg");
	while (__aload64(&recv_msgs->msgs) < 4) nsleep(100);
	ASSERT_EQ(__aload64(&recv_msgs->non_packet), 2, "non_packet messages");
	evh_stop(evh);
	evh_destroy(evh);
	close(cfd);
	munmap(recv_msgs, sizeof(EvhTestState));
}

Test(bptree1) {
	BpTreePage n;
	(void)n;
}

Test(db1) {
	u8 buffer[10] = "Hello1";
	i32 cfd, res;
	Db *db = NULL;
	struct sockaddr_in dest_addr = {.sin_family = AF_INET,
					.sin_addr = {htonl(0x7f000001U)}};
	struct iovec msgvec[1] = {
	    {.iov_base = &buffer, .iov_len = 6},
	};
	struct msghdr msg = {.msg_name = &dest_addr,
			     .msg_namelen = sizeof(dest_addr),
			     .msg_iov = msgvec,
			     .msg_iovlen = 1};
	DbConfig config = {
	    .queue_depth = 16,
	};

	ASSERT(!db_init(&db, &config), "db_init");

	cfd = socket(AF_INET, SOCK_DGRAM, 0);
	ASSERT(cfd > 0, "socket");
	dest_addr.sin_port = htons(db_port(db));

	res = sendmsg(cfd, &msg, 0);
	ASSERT_EQ(res, 6, "sendmsg");

	i32 pid = fork();
	ASSERT(pid >= 0, "fork");
	if (!pid) {
		db_start(db);
		exit_group(0);
	}

	u8 rx_buffer[32] = {0};

	struct iovec rx_iov = {
	    .iov_base = rx_buffer,
	    .iov_len = sizeof(rx_buffer),
	};

	struct msghdr rx_msg = {0};
	rx_msg.msg_iov = &rx_iov;
	rx_msg.msg_iovlen = 1;
	res = recvmsg(cfd, &rx_msg, 0);
	ASSERT_EQ(res, 6, "recvmsg");
	ASSERT(!memcmp(rx_buffer, "Hello1", 6), "buffer");

	fastmemcpy(buffer, "next\0\0", 6);
	msgvec[0].iov_len = 4;
	u64 micro_sum = 0, max = 0;
#define COUNT 1024
	for (u32 i = 0; i < COUNT; i++) {
		u64 timer = micros();
		res = sendmsg(cfd, &msg, 0);
		ASSERT_EQ(res, 4, "sendmsg2");
		res = recvmsg(cfd, &rx_msg, 0);
		timer = micros() - timer;
		if (timer > max) max = timer;
		micro_sum += timer;
		ASSERT_EQ(res, 4, "recvmsg2");
		ASSERT(!memcmp(rx_buffer, "next", 4), "buffer2");
	}
	println("avg lat = {},max={}", micro_sum / COUNT, max);

	db_stop(db);
	db_destroy(db);
	close(cfd);
}
