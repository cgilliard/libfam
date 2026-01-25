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

#include <libfam/iouring.h>
#include <libfam/linux.h>
#include <libfam/sync.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

Sync *__global_sync = NULL;

STATIC i32 global_sync_init(void) {
	if (__global_sync) return 0;
	return sync_init(&__global_sync);
}

PUBLIC i64 pwrite(i32 fd, const void *buf, u64 len, u64 offset) {
	struct io_uring_sqe sqe = {.opcode = IORING_OP_WRITE,
				   .addr = (u64)buf,
				   .fd = fd,
				   .len = len,
				   .off = offset,
				   .user_data = 1};
	if (global_sync_init() < 0) return -1;
	return sync_execute(__global_sync, sqe, true);
}

PUBLIC i32 usleep(u64 micros) {
	if (micros * 1000 < micros) ERR(EOVERFLOW);
	struct timespec ts = {.tv_nsec = micros * 1000};
	struct io_uring_sqe sqe = {.opcode = IORING_OP_TIMEOUT,
				   .addr = (u64)&ts,
				   .len = 1,
				   .user_data = 1};
	if (global_sync_init() < 0) return -1;
	return sync_execute(__global_sync, sqe, true);
}

PUBLIC i64 micros(void) {
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) < 0) return -1;
	return (i64)ts.tv_sec * 1000000LL + (i64)(ts.tv_nsec / 1000);
}

PUBLIC i64 write_num(i32 fd, u64 num) {
	u8 buf[21];
	u8 *p;
	u64 len;
	i64 written;
	if (fd < 0) ERR(EBADF);

	p = buf + sizeof(buf) - 1;
	*p = '\0';

	if (num == 0)
		*--p = '0';
	else
		while (num > 0) {
			*--p = '0' + (num % 10);
			num /= 10;
		}

	len = buf + sizeof(buf) - 1 - p;
	written = pwrite(fd, p, len, 0);
	if (written < 0) return -1;
	if ((u64)written != len) ERR(EIO);
	return 0;
}

