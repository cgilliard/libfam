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
#include <libfam/db.h>
#include <libfam/env.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>

struct Db {
	struct io_uring_params params;
	i32 ring_fd;
	i32 server_fd;
	u8 *sq_ring;
	u8 *cq_ring;
	struct io_uring_sqe *sqes;
	struct io_uring_cqe *cqes;
	u64 sq_ring_size;
	u64 cq_ring_size;
	u64 sqes_size;
	u32 *sq_tail;
	u32 *sq_array;
	u32 *cq_head;
	u32 *cq_tail;
	u32 *sq_mask;
	u32 *cq_mask;
	u16 port;
	u32 complete;
	u32 pid;
};

STATIC void db_handler(i32 sig) {}

STATIC i32 db_server_loop(Db *db, struct sockaddr_in *src_addr,
			  u8 buffer[DB_PACKET_SIZE],
			  struct io_uring_sqe *proc_recvmsg) {
	u32 flags = IORING_ENTER_GETEVENTS;
	i32 ret = 0, fd = db->ring_fd;
	u32 cq_mask = *db->cq_mask;
	u8 buffer_out[DB_PACKET_SIZE];
	struct iovec vec[1] = {{.iov_base = buffer_out}};
	struct msghdr message = {.msg_name = src_addr,
				 .msg_namelen = sizeof(struct sockaddr_in),
				 .msg_iov = vec,
				 .msg_iovlen = 1};

	struct io_uring_sqe sendmsg = {.opcode = IORING_OP_SENDMSG,
				       .flags = IOSQE_FIXED_FILE,
				       .addr = (u64)&message,
				       .user_data = U64_MAX - 1};

	while (!__aload32(&db->complete)) {
		u32 cq_head = *db->cq_head;
		u32 cq_tail = __aload32(db->cq_tail);
		u32 drained = cq_tail - cq_head;

		if (!drained) {
			i32 res = io_uring_enter2(fd, 0, 1, flags, NULL, 0);
			if (res < 0 && errno != EINTR) {
				ret = -1;
				break;
			}
		} else {
			for (u32 i = 0; i < drained; i++) {
				u32 idx = (cq_head + i) & cq_mask;
				u64 user_data = db->cqes[idx].user_data;
				i32 result = db->cqes[idx].res;

				if (result > 0 && result <= DB_PACKET_SIZE &&
				    user_data == U64_MAX) {
					fastmemcpy(buffer_out, buffer, result);
					sendmsg.len = result;

					vec[0].iov_len = result;

					u32 tail = *db->sq_tail;
					u32 index = tail & *db->sq_mask;
					db->sq_array[index] = index;
					db->sqes[index] = sendmsg;
					index = (tail + 1) & *db->sq_mask;
					db->sq_array[index] = index;
					db->sqes[index] = *proc_recvmsg;
					__aadd32(db->sq_tail, 2);

					i32 res = io_uring_enter2(fd, 2, 0, 0,
								  NULL, 0);
					if (res < 0 && errno != EINTR)
						return -1;
				}
			}
			__astore32(db->cq_head, cq_head + drained);
		}
	}
	return ret;
}

i32 db_init(Db **udb, DbConfig *config) {
	struct sockaddr_in addr = {.sin_family = AF_INET,
				   .sin_port = htons(config->port),
				   .sin_addr = {htonl(config->addr)}};
	Db *db = NULL;
	i32 res;
	u64 one = 1, addrlen = sizeof(addr);

	if (config->queue_depth < 2) {
		errno = EINVAL;
		return -1;
	}

	if ((db = smap(sizeof(Db))) == NULL) return -1;

	db->server_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (db->server_fd < 0) {
		db_destroy(db);
		return -1;
	}

	res = setsockopt(db->server_fd, SOL_SOCKET, SO_REUSEADDR, &one,
			 sizeof(one));

	if (res < 0) {
		db_destroy(db);
		return -1;
	}

	if (bind(db->server_fd, (void *)&addr, addrlen) < 0) {
		db_destroy(db);
		return -1;
	}

	if (getsockname(db->server_fd, (void *)&addr, &addrlen) < 0) {
		db_destroy(db);
		return -1;
	}

	db->port = ntohs(addr.sin_port);
	db->ring_fd = io_uring_setup(config->queue_depth, &db->params);
	if (db->ring_fd < 0) {
		db_destroy(db);
		return -1;
	}

	db->sq_ring_size =
	    db->params.sq_off.array + db->params.sq_entries * sizeof(u32);
	db->cq_ring_size = db->params.cq_off.cqes +
			   db->params.cq_entries * sizeof(struct io_uring_cqe);
	db->sqes_size = db->params.sq_entries * sizeof(struct io_uring_sqe);

	db->sq_ring = mmap(NULL, db->sq_ring_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, db->ring_fd, IORING_OFF_SQ_RING);

	if (db->sq_ring == MAP_FAILED) {
		db->sq_ring = NULL;
		db_destroy(db);
		return -1;
	}

	db->cq_ring = mmap(NULL, db->cq_ring_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, db->ring_fd, IORING_OFF_CQ_RING);

	if (db->cq_ring == MAP_FAILED) {
		db->cq_ring = NULL;
		db_destroy(db);
		return -1;
	}
	db->sqes = mmap(NULL, db->sqes_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			db->ring_fd, IORING_OFF_SQES);
	if (db->sqes == MAP_FAILED) {
		db->sqes = NULL;
		db_destroy(db);
		return -1;
	}

	db->sq_tail = (u32 *)(db->sq_ring + db->params.sq_off.tail);
	db->sq_array = (u32 *)(db->sq_ring + db->params.sq_off.array);
	db->cq_head = (u32 *)(db->cq_ring + db->params.cq_off.head);
	db->cq_tail = (u32 *)(db->cq_ring + db->params.cq_off.tail);
	db->sq_mask = (u32 *)(db->sq_ring + db->params.sq_off.ring_mask);

	db->cq_mask = (u32 *)(db->cq_ring + db->params.cq_off.ring_mask);
	db->cqes =
	    (struct io_uring_cqe *)(db->cq_ring + db->params.cq_off.cqes);

	if (io_uring_register(db->ring_fd, IORING_REGISTER_FILES,
			      (i32[]){db->server_fd}, 1) < 0) {
		db_destroy(db);
		return -1;
	}

	*udb = db;
	return 0;
}

i32 db_start(Db *db) {
	u8 buffer[DB_PACKET_SIZE];
	struct sockaddr_in src_addr = {0};
	struct iovec vec[1] = {{.iov_base = buffer, .iov_len = DB_PACKET_SIZE}};
	struct msghdr message = {.msg_name = &src_addr,
				 .msg_namelen = sizeof(src_addr),
				 .msg_iov = vec,
				 .msg_iovlen = 1};
	struct io_uring_sqe proc_recvmsg = {.opcode = IORING_OP_RECVMSG,
					    .flags = IOSQE_FIXED_FILE,
					    .addr = (u64)&message,
					    .len = sizeof(message),
					    .user_data = U64_MAX};

	struct rt_sigaction act = {0};
	act.k_sa_handler = db_handler;
	act.k_sa_flags = SA_RESTORER;
	act.k_sa_restorer = restorer;
	i32 v = rt_sigaction(SIGUSR1, &act, NULL, 8);
	if (v < 0) return -1;

	__astore32(&db->pid, getpid());
	u32 tail = *db->sq_tail;
	u32 index = tail & *db->sq_mask;
	db->sq_array[index] = index;
	db->sqes[index] = proc_recvmsg;
	__aadd32(db->sq_tail, 1);
	if (io_uring_enter2(db->ring_fd, 1, 0, 0, NULL, 0) < 0) return -1;

	i32 ret = db_server_loop(db, &src_addr, buffer, &proc_recvmsg);
	__astore32(&db->complete, 2);

	return ret;
}

i32 db_stop(Db *db) {
	u32 expected = 0;
	if (!__aload32(&db->pid)) {
		errno = ESRCH;
		return -1;
	}
	if (!__cas32(&db->complete, &expected, 1)) {
		errno = EALREADY;
		return -1;
	}
	kill(db->pid, SIGUSR1);
#if TEST == 1
	if (IS_VALGRIND()) {
		struct io_uring_sqe wakeup = {.opcode = IORING_OP_NOP};
		u32 tail = __aload32(db->sq_tail);
		u32 index = tail & *db->sq_mask;
		db->sq_array[index] = index;
		db->sqes[index] = wakeup;
		__aadd32(db->sq_tail, 1);
		io_uring_enter2(db->ring_fd, 1, 0, 0, NULL, 0);
	}
#endif /* TEST */
	while (__aload32(&db->complete) != 2);
	return 0;
}

void db_destroy(Db *db) {
	if (!db) return;
	if (db->sq_ring) munmap(db->sq_ring, db->sq_ring_size);
	db->sq_ring = NULL;
	if (db->cq_ring) munmap(db->cq_ring, db->cq_ring_size);
	db->cq_ring = NULL;
	if (db->sqes) munmap(db->sqes, db->sqes_size);
	db->sqes = NULL;
	if (db->ring_fd > 0) raw_close(db->ring_fd);
	db->ring_fd = -1;
	if (db->server_fd > 0) close(db->server_fd);
	db->server_fd = -1;
	munmap(db, sizeof(Db));
}
u16 db_port(Db *db) { return db->port; }

