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
#include <libfam/debug.h>
#include <libfam/linux.h>
#include <libfam/syscall.h>
#include <libfam/utils.h>

Async *__global_async = NULL;
static i32 __global_res = 0;

STATIC void global_async_callback(i32 res, u64 user_data, void *ctx) {
	__global_res = res;
}

STATIC i32 global_async_init(void) {
	if (__global_async) return 0;
	return async_init(&__global_async, 1, global_async_callback, NULL);
}

PUBLIC i64 pwrite(i32 fd, const void *buf, u64 len, u64 offset) {
	struct io_uring_sqe sqe = {.opcode = IORING_OP_WRITE,
				   .addr = (u64)buf,
				   .fd = fd,
				   .len = len,
				   .off = offset,
				   .user_data = 1};

#if TEST == 1
	if (_debug_pwrite_fail-- == 0) ERR(EIO);
	if ((fd == 1 || fd == 2) && _debug_no_write) return len;
#endif /* TEST */

	if (global_async_init() < 0) return -1;
	if (async_execute(__global_async, (struct io_uring_sqe[]){sqe}, 1,
			  true) < 0)
		return -1;
	if (__global_res < 0) ERR(-__global_res);
	return __global_res;
}

PUBLIC i64 pread(i32 fd, void *buf, u64 len, u64 offset) {
	struct io_uring_sqe sqe = {.opcode = IORING_OP_READ,
				   .addr = (u64)buf,
				   .fd = fd,
				   .len = len,
				   .off = offset,
				   .user_data = 1};
#if TEST == 1
	if (_debug_pread_fail-- == 0) ERR(EIO);
#endif /* TEST */

	if (global_async_init() < 0) return -1;
	if (async_execute(__global_async, (struct io_uring_sqe[]){sqe}, 1,
			  true) < 0)
		return -1;
	if (__global_res < 0) ERR(-__global_res);
	return __global_res;
}

PUBLIC i32 open(const u8 *path, i32 flags, u32 mode) {
	struct open_how how = {.flags = flags, .mode = mode};
	struct io_uring_sqe sqe = {.opcode = IORING_OP_OPENAT2,
				   .addr = (u64)path,
				   .fd = AT_FDCWD,
				   .len = sizeof(struct open_how),
				   .off = (u64)&how,
				   .user_data = 1};
	if (global_async_init() < 0) return -1;
	if (async_execute(__global_async, (struct io_uring_sqe[]){sqe}, 1,
			  true) < 0)
		return -1;
	if (__global_res < 0) ERR(-__global_res);
#if TEST == 1
	__aadd64(&open_fds, 1);
#endif /* TEST */
	return __global_res;
}

PUBLIC i32 close(i32 fd) {
	struct io_uring_sqe sqe = {
	    .opcode = IORING_OP_CLOSE, .fd = fd, .user_data = 1};
	if (global_async_init() < 0) return -1;
	if (async_execute(__global_async, (struct io_uring_sqe[]){sqe}, 1,
			  true) < 0)
		return -1;
	if (__global_res < 0) ERR(-__global_res);
#if TEST == 1
	__asub64(&open_fds, 1);
#endif /* TEST */
	return __global_res;
}

PUBLIC i32 fallocate(i32 fd, u64 new_size) {
	struct io_uring_sqe sqe = {.opcode = IORING_OP_FALLOCATE,
				   .fd = fd,
				   .addr = new_size,
				   .user_data = 1};
	if (global_async_init() < 0) return -1;
	if (async_execute(__global_async, (struct io_uring_sqe[]){sqe}, 1,
			  true) < 0)
		return -1;
	if (__global_res < 0) ERR(-__global_res);
	return __global_res;
}

PUBLIC i32 fsync(i32 fd) {
	struct io_uring_sqe sqe = {
	    .opcode = IORING_OP_FSYNC, .fd = fd, .user_data = 1};
	if (global_async_init() < 0) return -1;
	if (async_execute(__global_async, (struct io_uring_sqe[]){sqe}, 1,
			  true) < 0)
		return -1;
	if (__global_res < 0) ERR(-__global_res);
	return __global_res;
}

PUBLIC i32 fdatasync(i32 fd) {
	struct io_uring_sqe sqe = {.opcode = IORING_OP_FSYNC,
				   .fd = fd,
				   .user_data = 1,
				   .fsync_flags = IORING_FSYNC_DATASYNC};
	if (global_async_init() < 0) return -1;
	if (async_execute(__global_async, (struct io_uring_sqe[]){sqe}, 1,
			  true) < 0)
		return -1;
	if (__global_res < 0) ERR(-__global_res);
	return __global_res;
}

PUBLIC i32 nsleep(u64 nanos) {
	struct timespec ts = {.tv_nsec = nanos};
	struct io_uring_sqe sqe = {.opcode = IORING_OP_TIMEOUT,
				   .addr = (u64)&ts,
				   .len = 1,
				   .user_data = 1};
	if (global_async_init() < 0) return -1;
	if (async_execute(__global_async, (struct io_uring_sqe[]){sqe}, 1,
			  true) < 0)
		return -1;
	if (__global_res == -ETIME)
		return 0;
	else {
		if (__global_res < 0) errno = -__global_res;
		return __global_res < 0 ? -1 : __global_res;
	}
}

PUBLIC i32 usleep(u64 micros) {
	if (micros * 1000 < micros) ERR(EOVERFLOW);
	struct timespec ts = {.tv_nsec = micros * 1000};
	struct io_uring_sqe sqe = {.opcode = IORING_OP_TIMEOUT,
				   .addr = (u64)&ts,
				   .len = 1,
				   .user_data = 1};
	if (global_async_init() < 0) return -1;
	if (async_execute(__global_async, (struct io_uring_sqe[]){sqe}, 1,
			  true) < 0)
		return -1;
	if (__global_res == -ETIME)
		return 0;
	else {
		if (__global_res < 0) errno = -__global_res;
		return __global_res < 0 ? -1 : __global_res;
	}
}

PUBLIC i32 unlink(const u8 *pathname) {
	struct io_uring_sqe sqe = {.opcode = IORING_OP_UNLINKAT,
				   .fd = AT_FDCWD,
				   .addr = (u64)pathname,
				   .user_data = 1};
	if (global_async_init() < 0) return -1;
	if (async_execute(__global_async, (struct io_uring_sqe[]){sqe}, 1,
			  true) < 0)
		return -1;
	if (__global_res < 0) ERR(-__global_res);
	return __global_res;
}

PUBLIC i32 statx(const u8 *pathname, struct statx *st) {
	struct io_uring_sqe sqe = {.opcode = IORING_OP_STATX,
				   .fd = AT_FDCWD,
				   .addr = (u64)pathname,
				   .len = STATX_BASIC_STATS,
				   .off = (u64)st,
				   .user_data = 1};
	if (global_async_init() < 0) return -1;
	if (async_execute(__global_async, (struct io_uring_sqe[]){sqe}, 1,
			  true) < 0)
		return -1;
	if (__global_res < 0) ERR(-__global_res);
	return __global_res;
}

PUBLIC i32 waitpid(i32 pid) {
	u8 buf[1024] = {0};
	struct io_uring_sqe sqe = {.opcode = IORING_OP_WAITID,
				   .addr2 = (u64)buf,
				   .len = P_PID,
				   .fd = pid,
				   .file_index = WEXITED,
				   .user_data = 1};
	if (global_async_init() < 0) return -1;
	if (async_execute(__global_async, (struct io_uring_sqe[]){sqe}, 1,
			  true) < 0)
		return -1;
	if (__global_res < 0) ERR(-__global_res);
	return __global_res;
}

PUBLIC void *map(u64 length) {
	void *v = mmap(NULL, length, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (v == MAP_FAILED) return NULL;
	return v;
}
PUBLIC void *fmap(i32 fd, i64 size, i64 offset) {
	void *v =
	    mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
	if (v == MAP_FAILED) return NULL;
	return v;
}

PUBLIC void *smap(u64 length) {
	void *v = mmap(NULL, length, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (v == MAP_FAILED) return NULL;
	return v;
}

PUBLIC i64 micros(void) {
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) < 0) return -1;
	return (i64)ts.tv_sec * 1000000LL + (i64)(ts.tv_nsec / 1000);
}

PUBLIC void yield(void) {
#if defined(__x86_64__)
	__asm__ __volatile__("pause" ::: "memory");
#elif defined(__aarch64__)
	__asm__ __volatile__("yield" ::: "memory");
#endif
}

PUBLIC u64 cycle_counter(void) {
#if defined(__x86_64__)
	u32 lo, hi;
	mfence();
	__asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
	return ((u64)hi << 32) | lo;
#elif defined(__aarch64__)
	u64 cnt;
	__asm__ __volatile__("isb" : : : "memory");
	__asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(cnt));
	return cnt;
#else
#error "Unsupported architecture"
#endif
}

PUBLIC i32 fork(void) {
	i32 ret = clone(SIGCHLD, 0);
	if (!ret) __global_async = NULL;
	return ret;
}

PUBLIC i32 exists(const u8 *pathname) {
	i32 fd = open(pathname, O_RDWR, 0);
	if (fd > 0) {
		close(fd);
		return 1;
	}
	return 0;
}

i64 write_num(i32 fd, u64 num) {
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

