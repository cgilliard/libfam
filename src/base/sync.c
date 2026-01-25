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

#include <libfam/errno.h>
#include <libfam/iouring.h>
#include <libfam/linux.h>
#include <libfam/string.h>
#include <libfam/sync.h>
#include <libfam/syscall.h>

struct Sync {
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

i32 sync_init(Sync **s) {
	Sync *sync = NULL;

	sync = mmap(NULL, sizeof(Sync), PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (sync == MAP_FAILED) return -1;

	sync->sq_ring = NULL;
	sync->cq_ring = NULL;
	sync->sqes = NULL;
	sync->ring_fd = io_uring_setup(1, &sync->params);
	if (sync->ring_fd < 0) {
		sync_destroy(sync);
		return -1;
	}

	sync->sq_ring_size =
	    sync->params.sq_off.array + sync->params.sq_entries * sizeof(u32);
	sync->cq_ring_size =
	    sync->params.cq_off.cqes +
	    sync->params.cq_entries * sizeof(struct io_uring_cqe);
	sync->sqes_size = sync->params.sq_entries * sizeof(struct io_uring_sqe);

	sync->sq_ring = mmap(NULL, sync->sq_ring_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, sync->ring_fd, IORING_OFF_SQ_RING);

	if (sync->sq_ring == MAP_FAILED) {
		sync->sq_ring = NULL;
		sync_destroy(sync);
		return -1;
	}

	sync->cq_ring = mmap(NULL, sync->cq_ring_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, sync->ring_fd, IORING_OFF_CQ_RING);

	if (sync->cq_ring == MAP_FAILED) {
		sync->cq_ring = NULL;
		sync_destroy(sync);
		return -1;
	}
	sync->sqes = mmap(NULL, sync->sqes_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, sync->ring_fd, IORING_OFF_SQES);
	if (sync->sqes == MAP_FAILED) {
		sync->sqes = NULL;
		sync_destroy(sync);
	}

	sync->sq_tail = (u32 *)(sync->sq_ring + sync->params.sq_off.tail);
	sync->sq_array = (u32 *)(sync->sq_ring + sync->params.sq_off.array);
	sync->cq_head = (u32 *)(sync->cq_ring + sync->params.cq_off.head);
	sync->cq_tail = (u32 *)(sync->cq_ring + sync->params.cq_off.tail);
	sync->sq_mask = (u32 *)(sync->sq_ring + sync->params.sq_off.ring_mask);

	sync->cq_mask = (u32 *)(sync->cq_ring + sync->params.cq_off.ring_mask);
	sync->cqes =
	    (struct io_uring_cqe *)(sync->cq_ring + sync->params.cq_off.cqes);

	*s = sync;
	return 0;
}
i32 sync_execute(Sync *sync, const struct io_uring_sqe event, bool block) {
	i32 res;
	u32 index = *sync->sq_tail & *sync->sq_mask;
	u32 cq_head = *sync->cq_head, cq_tail, idx;
	sync->sq_array[index] = index;
	sync->sqes[index] = event;
	__atomic_fetch_add(sync->sq_tail, 1, __ATOMIC_SEQ_CST);
	res = io_uring_enter2(sync->ring_fd, 1, block ? 1 : 0, 0, NULL, 0);

	if (res >= 0) {
		if (!block) {
			do
				cq_tail = __atomic_load_n(sync->cq_tail,
							  __ATOMIC_ACQUIRE);
			while (cq_tail == cq_head);
		}
		idx = cq_head & *sync->cq_mask;
		if (sync->cqes[idx].res < 0) {
			res = -1;
			errno = -sync->cqes[idx].res;
		} else
			res = sync->cqes[idx].res;
	}

	__atomic_fetch_add(sync->cq_head, 1, __ATOMIC_RELEASE);

	return res < 0 ? -1 : res;
}
void sync_destroy(Sync *sync) {
	if (sync) {
		if (sync->sq_ring) munmap(sync->sq_ring, sync->sq_ring_size);
		sync->sq_ring = NULL;
		if (sync->cq_ring) munmap(sync->cq_ring, sync->cq_ring_size);
		sync->cq_ring = NULL;
		if (sync->sqes) munmap(sync->sqes, sync->sqes_size);
		sync->sqes = NULL;

		if (sync->ring_fd > 0) raw_close(sync->ring_fd);
		sync->ring_fd = -1;

		munmap(sync, sizeof(Sync));
	}
}

