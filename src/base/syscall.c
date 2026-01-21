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
#include <libfam/linux.h>
#include <libfam/types.h>
#include <libfam/utils.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif /* PAGE_SIZE */
#define PAGE_MASK (~(PAGE_SIZE - 1))

#ifdef __aarch64__
#define SYS_fchmod 52
#define SYS_close 57
#define SYS_utimesat 88
#define SYS_kill 129
#define SYS_rt_sigaction 134
#define SYS_getpid 172
#define SYS_bind 200
#define SYS_listen 201
#define SYS_getsockname 204
#define SYS_setsockopt 208
#define SYS_munmap 215
#define SYS_clone 220
#define SYS_mmap 222
#define SYS_clock_gettime 113
#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427
#elif defined(__x86_64__)
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_rt_sigaction 13
#define SYS_getpid 39
#define SYS_bind 49
#define SYS_getsockname 51
#define SYS_setsockopt 54
#define SYS_clone 56
#define SYS_kill 62
#define SYS_fchmod 91
#define SYS_clock_gettime 228
#define SYS_utimesat 261
#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427
#endif /* __x86_64__ */

i64 raw_syscall(i64 sysno, i64 a0, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5) {
	i64 result = 0;
#ifdef __aarch64__
	__asm__ volatile(
	    "mov x8, %1\n"
	    "mov x0, %2\n"
	    "mov x1, %3\n"
	    "mov x2, %4\n"
	    "mov x3, %5\n"
	    "mov x4, %6\n"
	    "mov x5, %7\n"
	    "svc #0\n"
	    "mov %0, x0\n"
	    : "=r"(result)
	    : "r"(sysno), "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
	    : "x0", "x1", "x2", "x3", "x4", "x5", "x8", "memory");
#elif defined(__x86_64__)
	register i64 _a3 __asm__("r10") = a3;
	register i64 _a4 __asm__("r8") = a4;
	register i64 _a5 __asm__("r9") = a5;
	__asm__ volatile("syscall"
			 : "=a"(result)
			 : "a"(sysno), "D"(a0), "S"(a1), "d"(a2), "r"(_a3),
			   "r"(_a4), "r"(_a5)
			 : "rcx", "r11", "memory");
#endif /* __x86_64__ */
	return result;
}

#ifdef __aarch64__
#define SYSCALL_EXIT                 \
	if (_debug_no_exit) return;  \
	__asm__ volatile(            \
	    "mov x8, #94\n"          \
	    "mov x0, %0\n"           \
	    "svc #0\n"               \
	    :                        \
	    : "r"((i64)status)       \
	    : "x8", "x0", "memory"); \
	while (true) {               \
	}
#elif defined(__x86_64__)
#define SYSCALL_EXIT                                     \
	if (_debug_no_exit) return;                      \
	__asm__ volatile(                                \
	    "movq $231, %%rax\n"                         \
	    "movq %0, %%rdi\n"                           \
	    "syscall\n"                                  \
	    :                                            \
	    : "r"((i64)status)                           \
	    : "%rax", "%rdi", "%rcx", "%r11", "memory"); \
	while (true) {                                   \
	}
#endif /* __x86_64__ */

#ifdef COVERAGE
void __gcov_dump(void);
#define SYSCALL_EXIT_COV                    \
	if (!_debug_no_exit) __gcov_dump(); \
	SYSCALL_EXIT
#endif /* COVERAGE */

PUBLIC void exit_group(i32 status) {
#ifdef COVERAGE
	SYSCALL_EXIT_COV
#else
	SYSCALL_EXIT
#endif
}

#define RETURN_VALUE(v)             \
	do {                        \
		if (v < 0) {        \
			errno = -v; \
			return -1;  \
		}                   \
		return v;           \
	} while (0);

i32 getpid(void) {
	i32 v;
	v = (i32)raw_syscall(SYS_getpid, 0, 0, 0, 0, 0, 0);
	RETURN_VALUE(v);
}

i32 bind(i32 sockfd, const struct sockaddr *addr, u64 addrlen) {
	i32 v;
	v = (i32)raw_syscall(SYS_bind, (i64)sockfd, (i64)addr, (i64)addrlen, 0,
			     0, 0);
	RETURN_VALUE(v);
}

i32 setsockopt(i32 socket, i32 level, i32 option_name, const void *option_value,
	       u64 option_len) {
	i32 v;
	v = (i32)raw_syscall(SYS_setsockopt, (i64)socket, (i64)level,
			     (i64)option_name, (i64)option_value, option_len,
			     0);
	RETURN_VALUE(v);
}

i32 getsockname(i32 sockfd, struct sockaddr *restrict addr,
		u64 *restrict addrlen) {
	i32 v;
	v = (i32)raw_syscall(SYS_getsockname, (i64)sockfd, (i64)addr,
			     (i64)addrlen, 0, 0, 0);
	RETURN_VALUE(v);
}

i32 kill(i32 pid, i32 signal) {
	i32 v;
	v = (i32)raw_syscall(SYS_kill, (i64)pid, (i64)signal, 0, 0, 0, 0);
	RETURN_VALUE(v);
}

void *mmap(void *addr, u64 length, i32 prot, i32 flags, i32 fd, i64 offset) {
	void *ret;
#if TEST == 1
	if (_debug_alloc_count-- == 0) return (void *)-1;
#endif /* TEST */

	ret = (void *)(u64)raw_syscall(SYS_mmap, (i64)addr, (i64)length,
				       (i64)prot, (i64)flags, (i64)fd, offset);
	if ((i64)ret < 0) {
		errno = -(i64)ret;
		return (void *)-1;
	} else {
#if TEST == 1
		__aadd64(&heap_bytes, (length + PAGE_SIZE - 1) & PAGE_MASK);
#endif /* TEST */
		return ret;
	}
}

i32 munmap(void *addr, u64 len) {
	i32 v;
	v = (i32)raw_syscall(SYS_munmap, (i64)addr, (i64)len, 0, 0, 0, 0);
	if (v < 0) {
		errno = -v;
		return -1;
	}

#if TEST == 1
	__asub64(&heap_bytes, (len + PAGE_SIZE - 1) & PAGE_MASK);
#endif /* TEST */

	return v;
}

i32 clone(i64 flags, void *sp) {
	i32 v;

	v = (i32)raw_syscall(SYS_clone, flags, (i64)sp, 0, 0, 0, 0);
	RETURN_VALUE(v);
}

i32 rt_sigaction(i32 signum, const struct rt_sigaction *act,
		 struct rt_sigaction *oldact, u64 sigsetsize) {
	i32 v;
	v = (i32)raw_syscall(SYS_rt_sigaction, (i64)signum, (i64)act,
			     (i64)oldact, (i64)sigsetsize, 0, 0);
	RETURN_VALUE(v);
}

i32 io_uring_setup(u32 entries, struct io_uring_params *params) {
	i32 v;

	v = (i32)raw_syscall(SYS_io_uring_setup, (i64)entries, (i64)params, 0,
			     0, 0, 0);
#if TEST == 1
	if (v >= 0) __aadd64(&open_fds, 1);
#endif /* TEST */
	RETURN_VALUE(v);
}
i32 io_uring_enter2(u32 fd, u32 to_submit, u32 min_complete, u32 flags,
		    void *arg, u64 sz) {
	i32 v;
#if TEST == 1
	if (_debug_io_uring_enter2_fail) return -1;
#endif /* TEST */

	v = (i32)raw_syscall(SYS_io_uring_enter, (i64)fd, (i64)to_submit,
			     (i64)min_complete, (i64)flags, (i64)arg, (i64)sz);
	RETURN_VALUE(v);
}

i32 io_uring_register(u32 fd, u32 opcode, void *arg, u32 nr_args) {
	i32 v;
	v = (i32)raw_syscall(SYS_io_uring_register, (i64)fd, (i64)opcode,
			     (i64)arg, (i64)nr_args, 0, 0);
	RETURN_VALUE(v);
}

i32 clock_gettime(i32 clockid, struct timespec *tp) {
	i32 v;
	v = (i32)raw_syscall(SYS_clock_gettime, (i64)clockid, (i64)tp, 0, 0, 0,
			     0);
	RETURN_VALUE(v);
}

#ifdef __aarch64__
#define SYSCALL_RESTORER     \
	__asm__ volatile(    \
	    "mov x8, #139\n" \
	    "svc #0\n" ::    \
		: "x8", "memory");
#elif defined(__x86_64__)
#define SYSCALL_RESTORER        \
	__asm__ volatile(       \
	    "movq $15, %%rax\n" \
	    "syscall\n"         \
	    :                   \
	    :                   \
	    : "%rax", "%rcx", "%r11", "memory");
#else
#error "Unsupported platform"
#endif /* ARCH */

#ifdef __aarch64__
void restorer(void) { SYSCALL_RESTORER; }
#elif defined(__x86_64__)
__attribute__((naked)) void restorer(void) { SYSCALL_RESTORER; }
#else
#error "Unsupported platform"
#endif /* ARCH */

i32 raw_close(i32 fd) {
	i32 v;
	v = (i32)raw_syscall(SYS_close, (i64)fd, 0, 0, 0, 0, 0);
#if TEST == 1
	if (!v) __asub64(&open_fds, 1);
#endif /* TEST */

	RETURN_VALUE(v);
}

PUBLIC i32 fchmod(i32 fd, u32 mode) {
	i32 v;
	v = (i32)raw_syscall(SYS_fchmod, (i64)fd, (i64)mode, 0, 0, 0, 0);
	RETURN_VALUE(v);
}

PUBLIC i32 utimesat(i32 dirfd, const u8 *pathname, const struct timeval *times,
		    i32 flags) {
	i32 v;
	v = (i32)raw_syscall(SYS_utimesat, (i64)dirfd, (i64)pathname,
			     (i64)times, (i64)flags, 0, 0);
	RETURN_VALUE(v);
}
