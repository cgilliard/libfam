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
#include <libfam/iouring.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

struct IoUring {
	u32 queue_depth;
	struct io_uring_params params;
	i32 ring_fd;
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
};

i32 iouring_init(IoUring **res, u32 queue_depth) {
	IoUring *iou = NULL;
INIT:
	iou = mmap(NULL, sizeof(IoUring), PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (iou == MAP_FAILED) ERROR();
	(iou)->sq_ring = NULL;
	(iou)->cq_ring = NULL;
	(iou)->sqes = NULL;
	(iou)->ring_fd = io_uring_setup(queue_depth, &(iou)->params);
	if ((iou)->ring_fd < 0) ERROR();

	(iou)->sq_ring_size =
	    (iou)->params.sq_off.array + (iou)->params.sq_entries * sizeof(u32);
	(iou)->cq_ring_size =
	    (iou)->params.cq_off.cqes +
	    (iou)->params.cq_entries * sizeof(struct io_uring_cqe);
	(iou)->sqes_size =
	    (iou)->params.sq_entries * sizeof(struct io_uring_sqe);
	(iou)->sq_ring = mmap(NULL, (iou)->sq_ring_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, (iou)->ring_fd, IORING_OFF_SQ_RING);
	if ((iou)->sq_ring == MAP_FAILED) ERROR();
	(iou)->cq_ring = mmap(NULL, (iou)->cq_ring_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, (iou)->ring_fd, IORING_OFF_CQ_RING);
	if ((iou)->cq_ring == MAP_FAILED) ERROR();
	(iou)->sqes = mmap(NULL, (iou)->sqes_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, (iou)->ring_fd, IORING_OFF_SQES);
	if ((iou)->sqes == MAP_FAILED) ERROR();

	(iou)->sq_tail = (u32 *)((iou)->sq_ring + (iou)->params.sq_off.tail);
	(iou)->sq_array = (u32 *)((iou)->sq_ring + (iou)->params.sq_off.array);
	(iou)->cq_head = (u32 *)((iou)->cq_ring + (iou)->params.cq_off.head);
	(iou)->cq_tail = (u32 *)((iou)->cq_ring + (iou)->params.cq_off.tail);
	(iou)->sq_mask =
	    (u32 *)((iou)->sq_ring + (iou)->params.sq_off.ring_mask);

	(iou)->cq_mask =
	    (u32 *)((iou)->cq_ring + (iou)->params.cq_off.ring_mask);
	(iou)->cqes =
	    (struct io_uring_cqe *)((iou)->cq_ring + (iou)->params.cq_off.cqes);

	(iou)->queue_depth = queue_depth;

	*res = iou;
CLEANUP:
	if (!IS_OK) iouring_destroy(iou);
	RETURN;
}

struct io_uring_sqe *iouring_get_sqe(IoUring *iou) {
	u32 tail = __aload32(iou->sq_tail);
	u32 head = __aload32(iou->cq_head);
	if (tail - head >= iou->queue_depth) return NULL;
	u32 index = tail & *iou->sq_mask;
	iou->sq_array[index] = index;
	return &iou->sqes[index];
}

i32 iouring_init_pread(IoUring *iou, i32 fd, void *buf, u64 len, u64 foffset,
		       u64 id, u32 flags) {
	struct io_uring_sqe *sqe;
	sqe = iouring_get_sqe(iou);
	if (!sqe) {
		errno = EBUSY;
		return -1;
	}

	fastmemset(sqe, 0, sizeof(*sqe));

	sqe->opcode = IORING_OP_READ;
	sqe->flags = flags;
	sqe->fd = fd;
	sqe->addr = (u64)buf;
	sqe->len = len;
	sqe->off = foffset;
	sqe->user_data = id;
	__aadd32(iou->sq_tail, 1);
	return 0;
}

i32 iouring_init_pread_fixed(IoUring *iou, i32 fd, void *buf, u64 len,
			     u64 foffset, u64 id, u32 flags) {
	struct io_uring_sqe *sqe;
	sqe = iouring_get_sqe(iou);
	if (!sqe) {
		errno = EBUSY;
		return -1;
	}

	fastmemset(sqe, 0, sizeof(*sqe));

	sqe->opcode = IORING_OP_READ_FIXED;
	sqe->flags = flags;
	sqe->fd = fd;
	sqe->addr = (u64)buf;
	sqe->len = len;
	sqe->off = foffset;
	sqe->user_data = id;
	__aadd32(iou->sq_tail, 1);
	return 0;
}

i32 iouring_init_pwrite(IoUring *iou, i32 fd, const void *buf, u64 len,
			u64 foffset, u64 id, u32 flags) {
	struct io_uring_sqe *sqe;
	sqe = iouring_get_sqe(iou);
	if (!sqe) {
		errno = EBUSY;
		return -1;
	}

	fastmemset(sqe, 0, sizeof(*sqe));

	sqe->opcode = IORING_OP_WRITE;
	sqe->flags = flags;
	sqe->fd = fd;
	sqe->addr = (u64)buf;
	sqe->len = len;
	sqe->off = foffset;
	sqe->user_data = id;
	__aadd32(iou->sq_tail, 1);
	return 0;
}

i32 iouring_init_pwrite_fixed(IoUring *iou, i32 fd, const void *buf, u64 len,
			      u64 foffset, u64 id, u32 flags) {
	struct io_uring_sqe *sqe;
	sqe = iouring_get_sqe(iou);
	if (!sqe) {
		errno = EBUSY;
		return -1;
	}

	fastmemset(sqe, 0, sizeof(*sqe));

	sqe->opcode = IORING_OP_WRITE_FIXED;
	sqe->flags = flags;
	sqe->fd = fd;
	sqe->addr = (u64)buf;
	sqe->len = len;
	sqe->off = foffset;
	sqe->user_data = id;
	__aadd32(iou->sq_tail, 1);
	return 0;
}

i32 iouring_init_openat(IoUring *iou, i32 dirfd, const char *path,
			struct open_how *how, u64 id) {
	struct io_uring_sqe *sqe = iouring_get_sqe(iou);
	if (!sqe) {
		errno = EBUSY;
		return -1;
	}

	fastmemset(sqe, 0, sizeof(*sqe));

	sqe->opcode = IORING_OP_OPENAT2;
	sqe->fd = dirfd;
	sqe->addr = (u64)path;
	sqe->len = sizeof(struct open_how);
	sqe->off = (u64)how;
	sqe->user_data = id;

	__aadd32(iou->sq_tail, 1);
	return 0;
}

i32 iouring_init_close(IoUring *iou, i32 fd, u64 id) {
	struct io_uring_sqe *sqe = iouring_get_sqe(iou);
	if (!sqe) {
		errno = EBUSY;
		return -1;
	}

	fastmemset(sqe, 0, sizeof(*sqe));

	sqe->opcode = IORING_OP_CLOSE;
	sqe->fd = fd;
	sqe->user_data = id;

	__aadd32(iou->sq_tail, 1);
	return 0;
}

i32 iouring_init_fallocate(IoUring *iou, i32 fd, u64 new_size, u64 id) {
	struct io_uring_sqe *sqe = iouring_get_sqe(iou);
	if (!sqe) {
		errno = EBUSY;
		return -1;
	}

	fastmemset(sqe, 0, sizeof(*sqe));

	sqe->opcode = IORING_OP_FALLOCATE;
	sqe->fd = fd;
	sqe->addr = new_size;
	sqe->len = 0;
	sqe->user_data = id;

	__aadd32(iou->sq_tail, 1);
	return 0;
}

i32 iouring_init_fsync(IoUring *iou, i32 fd, u64 id) {
	struct io_uring_sqe *sqe = iouring_get_sqe(iou);
	if (!sqe) {
		errno = EBUSY;
		return -1;
	}

	fastmemset(sqe, 0, sizeof(*sqe));

	sqe->opcode = IORING_OP_FSYNC;
	sqe->fd = fd;
	sqe->flags = IOSQE_IO_DRAIN | IOSQE_IO_HARDLINK;
	sqe->user_data = id;

	__aadd32(iou->sq_tail, 1);
	return 0;
}

i32 iouring_submit(IoUring *iou, u32 count) {
	return io_uring_enter2(iou->ring_fd, count, 0, 0, NULL, 0);
}

i32 iouring_spin(IoUring *iou, u64 *id) {
	u32 mask = *iou->cq_mask;
	i32 res;
	u32 hval;
	u64 user_data;
	do {
	begin_loop:
		hval = __aload32(iou->cq_head);
		u32 tval = __aload32(iou->cq_tail);

		if (hval == tval) {
			yield();
			goto begin_loop;
		}

		i32 cqe_idx = hval & mask;
		res = iou->cqes[cqe_idx].res;
		user_data = iou->cqes[cqe_idx].user_data;
	} while (!__cas32(iou->cq_head, &hval, hval + 1));
	*id = user_data;

	if (res < 0) {
		errno = -res;
		return -1;
	}

	return res;
}

i32 iouring_wait(IoUring *iou, u64 *id, u32 min_complete) {
	u32 head, tail, mask = *iou->cq_mask;
	for (;;) {
		head = __aload32(iou->cq_head);
		tail = __aload32(iou->cq_tail);
		if (head != tail) break;
		i32 ret = io_uring_enter2(iou->ring_fd, min_complete, 1,
					  IORING_ENTER_GETEVENTS, NULL, 0);

		(void)ret;
	}
	u32 idx = head & mask;
	i32 res = iou->cqes[idx].res;
	*id = iou->cqes[idx].user_data;
	__astore32(iou->cq_head, head + 1);

	if (res < 0) {
		errno = -res;
		return -1;
	}

	return res;
}

bool iouring_pending(IoUring *iou, u64 id) {
	u32 hval = __aload32(iou->cq_head);
	u32 tval = __aload32(iou->sq_tail);
	u32 mask = *iou->sq_mask;
	u32 index = hval;
	while (index < tval) {
		u32 sqe_idx = iou->sq_array[index & mask];
		if (iou->sqes[sqe_idx].user_data == id) return true;
		index++;
	}

	return false;
}

void iouring_destroy(IoUring *iou) {
	if (!iou) return;
	if (iou->sq_ring) munmap(iou->sq_ring, iou->sq_ring_size);
	if (iou->cq_ring) munmap(iou->cq_ring, iou->cq_ring_size);
	if (iou->sqes) munmap(iou->sqes, iou->sqes_size);
	iou->sq_ring = NULL;
	iou->cq_ring = NULL;
	iou->sqes = NULL;
	munmap(iou, sizeof(IoUring));
}

bool iouring_pending_all(IoUring *iou) {
	return __aload32(iou->cq_head) != __aload32(iou->sq_tail);
}

i32 iouring_ring_fd(IoUring *iou) { return iou->ring_fd; }
