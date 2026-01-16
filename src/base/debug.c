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

#include <libfam/debug.h>
#include <libfam/limits.h>

bool _debug_no_exit = false;
bool _debug_no_write = false;
bool _debug_fail_clone = false;
bool _debug_fail_fstat = false;
bool _debug_alloc_failure = false;
bool _debug_fork_fail = false;
bool _debug_compress_fail = false;
bool _debug_fail_io_uring_setup = false;
bool _debug_pwrite_0 = false;
i64 _debug_pwrite_fail = I64_MAX;
i64 _debug_pread_fail = I64_MAX;
i64 _debug_alloc_count = I64_MAX;

#if TEST == 1
extern u64 heap_bytes;
extern u64 open_fds;
u64 get_heap_bytes(void) { return heap_bytes; }
void heap_bytes_reset(void) { heap_bytes = 0; }
u64 get_open_fds(void) { return open_fds; }
void open_fds_reset(void) { open_fds = 0; }
#endif /* TEST */

