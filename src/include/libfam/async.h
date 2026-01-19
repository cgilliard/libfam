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

#ifndef _ASYNC_H
#define _ASYNC_H

#include <libfam/types.h>

typedef void (*AsyncCallback)(i32 res, u64 user_data, void *ctx);
typedef void (*AsyncStartLoop)(void *ctx);

typedef struct Async Async;
struct io_uring_sqe;

i32 async_init(Async **async, u32 queue_depth, AsyncCallback callback,
	       AsyncStartLoop startloop, void *ctx);
u32 async_queue_depth(Async *async);
i32 async_schedule(Async *async, const struct io_uring_sqe *events, u32 count);
i32 async_process(Async *async);
i32 async_stop(Async *async);
i32 async_execute(Async *async, const struct io_uring_sqe *events, u32 count,
		  bool wait);
i32 async_ring_fd(Async *async);
void async_destroy(Async *async);

#if TEST == 1
void async_add_queue(Async *async);
void async_sub_queue(Async *async);
#endif /* TEST */

#endif /* _ASYNC_H */
