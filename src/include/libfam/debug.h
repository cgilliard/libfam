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

#ifndef _DEBUG_H
#define _DEBUG_H

#include <libfam/types.h>

extern bool _debug_no_exit;

#if TEST == 1
extern bool _debug_no_write;
extern bool _debug_fail_getsockbyname;
extern bool _debug_fail_pipe2;
extern bool _debug_fail_listen;
extern bool _debug_fail_setsockopt;
extern bool _debug_fail_fcntl;
extern bool _debug_fail_epoll_create1;
extern bool _debug_fail_clone;
extern bool _debug_bible_invalid_hash;
extern bool _debug_alloc_failure;
extern bool _debug_no_aesni;
extern bool _debug_fail_fstat;
extern bool _debug_fork_fail;
extern bool _debug_compress_fail;
extern bool _debug_fail_io_uring_setup;
extern bool _debug_pwrite_0;
extern i64 _debug_pwrite_fail;
extern i64 _debug_pread_fail;
extern i64 _debug_alloc_count;

u64 get_heap_bytes(void);
void heap_bytes_reset(void);
u64 get_open_fds(void);
void open_fds_reset(void);
#endif /* TEST */

#endif /* _DEBUG_H */

