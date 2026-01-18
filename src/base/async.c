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
#include <libfam/errno.h>
#include <libfam/linux.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

struct Async {
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
	AsyncCallback callback;
	void *ctx;
};

#if TEST == 1
void async_add_queue(Async *async) { __aadd32(async->sq_tail, 1); }
void async_sub_queue(Async *async) { __asub32(async->sq_tail, 1); }
#endif /* TEST */

i32 async_init(Async **ret, u32 queue_depth, AsyncCallback callback,
	       void *ctx) {
	Async *async = NULL;

	if ((async = smap(sizeof(Async))) == NULL) return -1;

	async->sq_ring = NULL;
	async->cq_ring = NULL;
	async->sqes = NULL;
	async->ring_fd = io_uring_setup(queue_depth, &async->params);
	if (async->ring_fd < 0) {
		async_destroy(async);
		return -1;
	}

	async->sq_ring_size =
	    async->params.sq_off.array + async->params.sq_entries * sizeof(u32);
	async->cq_ring_size =
	    async->params.cq_off.cqes +
	    async->params.cq_entries * sizeof(struct io_uring_cqe);
	async->sqes_size =
	    async->params.sq_entries * sizeof(struct io_uring_sqe);

	async->sq_ring = mmap(NULL, async->sq_ring_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, async->ring_fd, IORING_OFF_SQ_RING);

	if (async->sq_ring == MAP_FAILED) {
		async->sq_ring = NULL;
		async_destroy(async);
		return -1;
	}

	async->cq_ring = mmap(NULL, async->cq_ring_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, async->ring_fd, IORING_OFF_CQ_RING);

	if (async->cq_ring == MAP_FAILED) {
		async->cq_ring = NULL;
		async_destroy(async);
		return -1;
	}
	async->sqes = mmap(NULL, async->sqes_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, async->ring_fd, IORING_OFF_SQES);
	if (async->sqes == MAP_FAILED) {
		async->sqes = NULL;
		async_destroy(async);
		return -1;
	}

	async->sq_tail = (u32 *)(async->sq_ring + async->params.sq_off.tail);
	async->sq_array = (u32 *)(async->sq_ring + async->params.sq_off.array);
	async->cq_head = (u32 *)(async->cq_ring + async->params.cq_off.head);
	async->cq_tail = (u32 *)(async->cq_ring + async->params.cq_off.tail);
	async->sq_mask =
	    (u32 *)(async->sq_ring + async->params.sq_off.ring_mask);

	async->cq_mask =
	    (u32 *)(async->cq_ring + async->params.cq_off.ring_mask);
	async->cqes =
	    (struct io_uring_cqe *)(async->cq_ring + async->params.cq_off.cqes);

	async->queue_depth = queue_depth;
	async->callback = callback;
	async->ctx = ctx;

	*ret = async;
	return 0;
}

STATIC i32 async_proc_execute(Async *async, struct io_uring_sqe *events,
			      u32 count) {
	u32 tail = *async->sq_tail;
	u32 head = *async->cq_head;
	u32 depth = async->params.sq_entries;

	if (__builtin_expect(count > depth, 0)) {
		errno = EINVAL;
		return -1;
	}

	if (__builtin_expect(tail - head >= (depth - (count - 1)), 0)) {
		errno = EBUSY;
		return -1;
	}

	for (u64 i = 0; i < count; i++) {
		u32 index = (tail + i) & *async->sq_mask;
		async->sq_array[index] = index;
		fastmemcpy(&async->sqes[index], &events[i],
			   sizeof(struct io_uring_sqe));
	}

	__aadd32(async->sq_tail, count);
	return 0;
}

i32 async_execute_only(Async *async, struct io_uring_sqe *events, u32 count) {
	if (async_proc_execute(async, events, count) < 0) return -1;
	return io_uring_enter2(async->ring_fd, count, 0, IORING_ENTER_GETEVENTS,
			       NULL, 0);
}

i32 async_execute(Async *async, struct io_uring_sqe *events, u32 count,
		  bool wait) {
	u32 tail = *async->sq_tail, drained;
	u32 head = *async->cq_head;
	u32 mask = *async->cq_mask;

	if (async_proc_execute(async, events, count) < 0) return -1;
	if (__builtin_expect(count || (__aload32(async->cq_tail) != head), 1)) {
		i32 res = io_uring_enter2(async->ring_fd, count, wait ? 1 : 0,
					  IORING_ENTER_GETEVENTS, NULL, 0);
		if (res < 0) return -1;
	}
	tail = __aload32(async->cq_tail);

	drained = tail - head;
	for (u32 i = 0; i < drained; i++) {
		u32 idx = (head + i) & mask;
		u64 user_data = async->cqes[idx].user_data;
		i32 result = async->cqes[idx].res;
		async->callback(result, user_data, async->ctx);
	}
	__astore32(async->cq_head, head + drained);
	return drained;
}

void async_destroy(Async *async) {
	if (async) {
		if (async->sq_ring) munmap(async->sq_ring, async->sq_ring_size);
		async->sq_ring = NULL;
		if (async->cq_ring) munmap(async->cq_ring, async->cq_ring_size);
		async->cq_ring = NULL;
		if (async->sqes) munmap(async->sqes, async->sqes_size);
		async->sqes = NULL;
		munmap(async, sizeof(Async));
	}
}

