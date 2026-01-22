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

#ifndef _COMPRESS_H
#define _COMPRESS_H

#include <libfam/types.h>

#define MAX_COMPRESS_LEN (1 << 18)

u64 compress_bound(u64 source_len);
i32 compress_block(const u8 *in, u32 len, u8 *out, u32 capacity);
i32 decompress_block(const u8 *in, u32 len, u8 *out, u32 capacity);
i32 compress_file(i32 infd, u64 in_offset, i32 outfd, u64 out_offset);
i32 decompress_file(i32 infd, u64 in_offset, i32 outfd, u64 out_offset);
i32 compress_stream(i32 infd, u64 in_offset, i32 outfd, u64 out_offset);
i32 decompress_stream(i32 infd, u64 in_offset, i32 outfd, u64 out_offset);

#endif /* _COMPRESS_H */
