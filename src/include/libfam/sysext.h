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

#ifndef _SYSEXT_H
#define _SYSEXT_H

#include <libfam/types.h>

struct statx;
struct sockaddr;
struct msghdr;

void yield(void);
void __global_sync_shutdown(void);
u64 cycle_counter(void);
i64 write_num(i32 fd, u64 value);
i64 pwrite(i32 fd, const void *buf, u64 len, u64 offset);
i64 pread(i32 fd, void *buf, u64 len, u64 offset);
i32 open(const u8 *path, i32 flags, u32 mode);
i32 fallocate(i32 fd, u64 new_size);
i32 fsync(i32 fd);
i32 fstatx(i32 fd, struct statx *st);
i64 fsize(i32 fd);
i32 fdatasync(i32 fd);
i32 close(i32 fd);
i64 micros(void);
i32 nsleep(u64 nsec);
i32 usleep(u64 usec);
i32 fork(void);
i32 unlink(const u8 *path);
i32 waitpid(i32 pid);
void *map(u64 length);
void *fmap(i32 fd, i64 size, i64 offset);
void *smap(u64 length);
i32 exists(const u8 *path);
i32 statx(const u8 *pathname, struct statx *st);
i32 socket(i32 domain, i32 type, i32 protocol);
i64 sendmsg(i32 socket, const struct msghdr *message, i32 flags);
i64 recvmsg(i32 socket, struct msghdr *message, i32 flags);
i64 bind(i32 sockfd, const struct sockaddr *addr, u64 addrlen);

#endif /* _SYSEXT_H */
