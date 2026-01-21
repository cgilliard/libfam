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

#ifndef _SYSCALL_H
#define _SYSCALL_H

#include <libfam/net.h>
#include <libfam/types.h>

struct rt_sigaction;
struct io_uring_params;
struct timespec;
struct timeval;
struct stat;

i32 clock_gettime(i32 clockid, struct timespec *tp);
void *mmap(void *addr, u64 length, i32 prot, i32 flags, i32 fd, i64 offset);
i32 munmap(void *addr, u64 len);
i32 clone(i64 flags, void *sp);
void exit_group(i32 status);
i32 io_uring_setup(u32 entries, struct io_uring_params *params);
i32 io_uring_enter2(u32 fd, u32 to_submit, u32 min_complete, u32 flags,
		    void *arg, u64 sz);
i32 io_uring_register(u32 fd, u32 opcode, void *arg, u32 nr_args);
i32 fchmod(i32 fd, u32 mode);
i32 utimesat(i32 dirfd, const u8 *path, const struct timeval *times, i32 flags);
i32 rt_sigaction(i32 signum, const struct rt_sigaction *act,
		 struct rt_sigaction *oldact, u64 sigsetsize);
void restorer(void);
i32 getpid(void);
i32 kill(i32 pid, i32 signal);

i32 setsockopt(i32 socket, i32 level, i32 option_name, const void *option_value,
	       i64 option_len);
i32 getsockname(i32 sockfd, struct sockaddr *restrict addr,
		i64 *restrict addrlen);
i32 raw_close(i32 fd);

#endif /* _SYSCALL_H */
