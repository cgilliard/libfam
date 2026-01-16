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
#include <libfam/debug.h>
#include <libfam/iouring.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

u64 open_fds = 0;
IoUring *__global_iou__ = NULL;

i32 global_iou_init(void) {
	if (__global_iou__) return 0;
	return iouring_init(&__global_iou__, 1);
}

PUBLIC i64 pwrite(i32 fd, const void *buf, u64 len, u64 offset) {
	u64 id;
	i64 res;
#if TEST == 1
	if (_debug_pwrite_0) return 0;
	if (_debug_pwrite_fail-- == 0) {
		errno = EIO;
		return -1;
	}
	if ((fd == 1 || fd == 2) && _debug_no_write) return len;
#endif /* TEST */

	if (global_iou_init() < 0) return -1;
	res = iouring_init_pwrite(__global_iou__, fd, buf, len, offset, U64_MAX,
				  IOSQE_IO_LINK);
	if (res < 0) return -1;
	return iouring_wait(__global_iou__, &id, 1);
}

PUBLIC i64 pread(i32 fd, void *buf, u64 len, u64 offset) {
	u64 id;
	i64 res;

#if TEST == 1
	if (_debug_pread_fail-- == 0) {
		errno = EIO;
		return -1;
	}
#endif /* TEST */

	if (global_iou_init() < 0) return -1;
	res = iouring_init_pread(__global_iou__, fd, buf, len, offset, U64_MAX,
				 0);
	if (res < 0) return -1;
	return iouring_wait(__global_iou__, &id, 1);
}

i32 open(const u8 *path, i32 flags, u32 mode) {
	u64 id;
	struct open_how how = {.flags = flags, .mode = mode};
	i64 res;

	if (global_iou_init() < 0) return -1;
	res = iouring_init_openat(__global_iou__, AT_FDCWD, (void *)path, &how,
				  U64_MAX);
	if (res < 0) return -1;
	res = iouring_wait(__global_iou__, &id, 1);
#if TEST == 1
	if (res >= 0) __aadd64(&open_fds, 1);
#endif /* TEST */

	return res;
}

PUBLIC i32 close(i32 fd) {
	u64 id;
	i64 res;

	if (global_iou_init() < 0) return -1;
	res = iouring_init_close(__global_iou__, fd, U64_MAX);
	if (res < 0) return -1;
	res = iouring_wait(__global_iou__, &id, 1);
#if TEST == 1
	if (res >= 0) __asub64(&open_fds, 1);
#endif /* TEST */

	return res;
}

PUBLIC i32 fallocate(i32 fd, u64 new_size) {
	u64 id;
	i64 res;

	if (global_iou_init() < 0) return -1;
	res = iouring_init_fallocate(__global_iou__, fd, new_size, U64_MAX);
	if (res < 0) return -1;
	res = iouring_wait(__global_iou__, &id, 1);
	return res;
}

PUBLIC i32 fsync(i32 fd) {
	u64 id;
	i64 res;

	if (global_iou_init() < 0) return -1;
	res = iouring_init_fsync(__global_iou__, fd, U64_MAX);
	if (res < 0) return -1;
	res = iouring_wait(__global_iou__, &id, 1);
	return res;
}

PUBLIC i32 nsleep(u64 nsec) {
	struct timespec ts = {.tv_sec = (nsec / 1000000000ULL),
			      .tv_nsec = (nsec % 1000000000ULL)};
	return nanosleep(&ts, &ts);
}

PUBLIC i32 usleep(u64 usec) { return nsleep(usec * 1000); }

PUBLIC i32 fork(void) {
#if TEST == 1
	if (_debug_fork_fail) return -1;
#endif /* TEST */
	i32 ret = clone(SIGCHLD, 0);
	if (!ret) __global_iou__ = NULL;
	return ret;
}

PUBLIC i64 micros(void) {
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) < 0) return -1;
	return (i64)ts.tv_sec * 1000000LL + (i64)(ts.tv_nsec / 1000);
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

i32 await(i32 pid) {
	u8 buf[1024] = {0};
	return waitid(P_PID, pid, buf, WEXITED);
}

PUBLIC i64 fsize(i32 fd) {
	struct stat st;
	i32 res = fstat(fd, &st);
	return res < 0 ? -1 : st.st_size;
}

PUBLIC i32 unlink(const u8 *path) { return unlinkat(AT_FDCWD, path, 0); }

PUBLIC i32 file(const u8 *path) { return open(path, O_CREAT | O_RDWR, 0600); }

PUBLIC i32 exists(const u8 *path) {
	i32 fd = open(path, O_RDWR, 0);
	if (fd > 0) {
		close(fd);
		return 1;
	}
	return 0;
}

PUBLIC i64 write_num(i32 fd, u64 num) {
	u8 buf[21];
	u8 *p;
	u64 len;
	i64 written;
	if (fd < 0) {
		errno = EBADF;
		return -1;
	}

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
	if ((u64)written != len) {
		errno = EIO;
		return -1;
	}
	return 0;
}

void yield(void) {
#if defined(__x86_64__)
	__asm__ __volatile__("pause" ::: "memory");
#elif defined(__aarch64__)
	__asm__ __volatile__("yield" ::: "memory");
#endif
}

u64 cycle_counter(void) {
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

