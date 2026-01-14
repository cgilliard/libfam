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

#ifndef _IO_URING_H
#define _IO_URING_H

#include <libfam/types.h>

typedef struct IoUring IoUring;
struct io_uring_sqe;
struct open_how;

i32 iouring_init(IoUring **iou, u32 queue_depth);
i32 iouring_prep(IoUring *iou, struct io_uring_sqe event);
i32 iouring_init_pread(IoUring *iou, i32 fd, void *buf, u64 len, u64 foffset,
		       u64 id, u32 flags);
i32 iouring_init_pwrite(IoUring *iou, i32 fd, const void *buf, u64 len,
			u64 foffset, u64 id, u32 flags);
i32 iouring_init_pread_fixed(IoUring *iou, i32 fd, void *buf, u64 len,
			     u64 foffset, u64 id, u32 flags);
i32 iouring_init_pwrite_fixed(IoUring *iou, i32 fd, const void *buf, u64 len,
			      u64 foffset, u64 id, u32 flags);
i32 iouring_init_fsync(IoUring *iou, i32 fd, u64 id);
i32 iouring_init_openat(IoUring *iou, i32 dirfd, const char *path,
			struct open_how *how, u64 id);
i32 iouring_init_close(IoUring *iou, i32 fd, u64 id);
i32 iouring_init_fallocate(IoUring *iou, i32 fd, u64 new_size, u64 id);
i32 iouring_submit(IoUring *iou, u32 count);
i32 iouring_spin(IoUring *iou, u64 *id);
i32 iouring_wait(IoUring *iou, u64 *id, u32 to_submit);
void iouring_destroy(IoUring *iou);
i32 iouring_ring_fd(IoUring *iou);
bool iouring_pending(IoUring *iou, u64 id);
bool iouring_pending_all(IoUring *iou);

#endif /* _IO_URING_H */
