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

#ifndef _BIBLE_H
#define _BIBLE_H

#include <libfam/types.h>

#define HASH_INPUT_LEN 128
#define BIBLE_UNCOMPRESSED_SIZE 4634229

typedef struct Bible Bible;

const Bible *bible_gen(bool print_status);
const Bible *bible_load(const u8 *path);
i32 bible_store(const Bible *b, const u8 *path);
void bible_expand(const Bible *b, u8 bible[BIBLE_UNCOMPRESSED_SIZE]);
void bible_sbox8_64(u64 sbox[256]);
void bible_hash(const Bible *b, const u8 input[HASH_INPUT_LEN], u8 out[32],
		const u64 sbox[256]);
i32 mine_block(const Bible *bible, const u8 header[HASH_INPUT_LEN],
	       const u8 target[32], u8 out[32], u32 *nonce, u32 max_iter,
	       u64 sbox[256]);
void bible_destroy(const Bible *b);

#endif /* _BIBLE_H */
