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

#include <libfam/types.h>
#include <libfam/utils.h>

STATIC_ASSERT(sizeof(u8) == 1, u8_sizes_match);
STATIC_ASSERT(sizeof(i8) == 1, i8_sizes_match);
STATIC_ASSERT(sizeof(u16) == 2, u16_sizes_match);
STATIC_ASSERT(sizeof(i16) == 2, i16_sizes_match);
STATIC_ASSERT(sizeof(u32) == 4, u32_sizes_match);
STATIC_ASSERT(sizeof(i32) == 4, i32_sizes_match);
STATIC_ASSERT(sizeof(u64) == 8, u64_sizes_match);
STATIC_ASSERT(sizeof(i64) == 8, i64_sizes_match);
STATIC_ASSERT(sizeof(u128) == 16, u128_sizes_match);
STATIC_ASSERT(sizeof(i128) == 16, i128_sizes_match);
STATIC_ASSERT(sizeof(f64) == 8, f64_sizes_match);
STATIC_ASSERT(sizeof(void *) == 8, os_64_bit);
STATIC_ASSERT(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, little_endian);
