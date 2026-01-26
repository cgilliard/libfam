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

#include <libfam/bible.h>
#include <libfam/compress.h>
#include <libfam/env.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/storm.h>
#include <libfam/test.h>

Test(compress) {
	const u8 *path = "./resources/test_wikipedia.txt";
	i32 fd = open(path, O_RDWR, 0);
	u32 size = fsize(fd);
	u8 *in = fmap(fd, size, 0);
	ASSERT(in, "fmap");
	u8 out[100000] = {0}, verify[100000] = {0};
	i32 result = compress_block(in, size, out, sizeof(out));
	result = decompress_block(out, result, verify, sizeof(verify));
	ASSERT_EQ(size, result, "size");
	ASSERT(!memcmp(in, verify, size), "verify");
	munmap(in, size);
	close(fd);
}

Test(compress2) {
	u8 out[1024] = {0}, verify[10];
	ASSERT_EQ(compress_block("1", 1, out, sizeof(out)), 4, "raw block");
	ASSERT_EQ(decompress_block(out, 4, verify, sizeof(verify)), 1,
		  "raw decomp");
	ASSERT(!memcmp(verify, "1", 1), "verify");
	ASSERT_EQ(decompress_block("a", 1, out, sizeof(out)), -1, "overflow");
	ASSERT_EQ(decompress_block(NULL, 0, NULL, 0), -1, "einval");

	ASSERT_EQ(compress_block(NULL, 0, NULL, 0), -1, "efault");
	ASSERT_EQ(errno, EFAULT, "efault errno");
	ASSERT_EQ(compress_block("0123456789", 10, out, 3), -1, "einval");
	ASSERT_EQ(errno, EINVAL, "einval errno");
	ASSERT_EQ(compress_block("", 0, out, sizeof(out)), 3, "zero len str");
	ASSERT_EQ(decompress_block(out, 3, verify, sizeof(verify)), 0,
		  "zer len decomp");
}

i32 compress_read_block(const u8 *in, u32 len, u8 *out, u32 capacity);
i32 compress_read_raw(const u8 *in, u32 len, u8 *out, u32 capacity);

Test(compress_special_cases) {
	u8 block[16384] = {0}, out[2048];
	ASSERT_EQ(compress_read_block("", 0, NULL, 0), -1, "too small");
	ASSERT_EQ(compress_read_block(block, 16384, out, sizeof(out)), -1,
		  "read block overflow");
	ASSERT_EQ(compress_read_raw("", 0, out, sizeof(out)), -1, "len<3");
	ASSERT_EQ(compress_read_raw("abc", 3, out, sizeof(out)), -1,
		  "len==3 bad val");
	ASSERT_EQ(compress_read_raw("abcd", 4, out, 0), -1,
		  "block_len > capacity");
	__builtin_memset(block, 0xFF, sizeof(block));
	block[0] = 0;
	block[1] = 1;
	block[2] = 0;
	ASSERT_EQ(compress_read_raw(block, 100, out, sizeof(out)), -1,
		  "read raw");
}

Test(compress_cut_off) {
	const u8 *path = "./resources/test_min.txt";
	i32 fd = open(path, O_RDWR, 0);
	u32 size = fsize(fd);
	u8 *in = fmap(fd, size, 0);
	ASSERT(in, "fmap");
	u8 out[100000] = {0}, verify[100000] = {0};
	i32 result = compress_block(in, size, out, sizeof(out));
	ASSERT_EQ(compress_read_block(out, result, verify, 1000), -1,
		  "cut off");
	munmap(in, size);
	close(fd);
}

#define BIBLE_PATH "resources/test_bible.dat"

Test(bible) {
	const Bible *b;
	u64 sbox[256];
	__attribute__((aligned(32))) static const u8 input[128] = {
	    1,	2,  3,	4,  5,	6,  7,	8,  9,	10, 11, 12, 13, 14, 15, 16,
	    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
	__attribute__((aligned(32))) u8 output[32];

	if (!exists(BIBLE_PATH)) {
		if (IS_VALGRIND()) return;
		b = bible_gen(true);
		bible_store(b, BIBLE_PATH);
	} else
		b = bible_load(BIBLE_PATH);

	bible_sbox8_64(sbox);
	bible_hash(b, input, output, sbox);

	u8 expected[32] = {65, 229, 114, 172, 92,  145, 119, 123, 197, 180, 165,
			   88, 178, 42,	 104, 69,  194, 222, 84,  105, 136, 8,
			   80, 225, 180, 104, 222, 54,	137, 45,  62,  205};

	ASSERT(!memcmp(output, expected, 32), "hash");
	bible_destroy(b);
	b = bible_load(BIBLE_PATH);
	bible_destroy(b);
}

Test(bible_mine) {
	const Bible *b;
	u32 nonce = 0;
	u64 sbox[256];
	__attribute__((aligned(32))) u8 output[32] = {0};
	u8 target[32];
	__attribute((aligned(32))) u8 header[HASH_INPUT_LEN];

	for (u32 i = 0; i < HASH_INPUT_LEN; i++) header[i] = i;

	if (!exists(BIBLE_PATH)) {
		if (IS_VALGRIND()) return;
		b = bible_gen(false);
		bible_store(b, BIBLE_PATH);
	} else
		b = bible_load(BIBLE_PATH);

	memset(target, 0xFF, 32);
	target[0] = 0;
	target[1] = 0;
	bible_sbox8_64(sbox);
	mine_block(b, header, target, output, &nonce, U32_MAX, sbox);

	ASSERT_EQ(nonce, 45890, "nonce");
	ASSERT(!memcmp(output, (u8[]){0,   0,	178, 28,  75,  191, 58,	 214,
				      17,  30,	146, 59,  42,  211, 72,	 59,
				      10,  5,	143, 171, 234, 121, 165, 205,
				      143, 221, 59,  50,  245, 97,  236, 73},
		       32),
	       "hash");
	bible_destroy(b);
}

Test(bible_dat) {
	u8 *bible;
	__attribute__((aligned(32))) static const u8 BIBLE_GEN_DOMAIN[32] = {
	    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15, 0x85, 0xeb,
	    0xca, 0x6b, 0xc2, 0xb2, 0xae, 0x35, 0x51, 0x7c, 0xc1, 0xb7,
	    0x27, 0x22, 0x0a, 0x95, 0x07, 0x00, 0x00, 0x01};
	StormContext ctx;
	const Bible *b;

	bible = map(BIBLE_UNCOMPRESSED_SIZE);
	ASSERT(bible, "map");

	if (!exists(BIBLE_PATH)) {
		if (IS_VALGRIND()) return;
		b = bible_gen(true);
		bible_store(b, BIBLE_PATH);
	} else
		b = bible_load(BIBLE_PATH);

	bible_expand(b, bible);

	storm_init(&ctx, BIBLE_GEN_DOMAIN);
	__attribute__((aligned(32))) u8 buffer[32];
	u64 off = 0;
	while (off < (BIBLE_UNCOMPRESSED_SIZE & ~31U)) {
		__builtin_memcpy(buffer, bible + off, 32);
		storm_next_block(&ctx, buffer);
		off += 32;
	}

	const u8 *check =
	    "Genesis||1||1||In the beginning God created the heaven "
	    "and the "
	    "earth.";

	ASSERT(!__builtin_memcmp(bible, check, strlen(check)), "first verse");
	ASSERT(!__builtin_memcmp(
		   buffer,
		   (u8[]){40,  57,  160, 40,  170, 236, 126, 115, 174, 135, 8,
			  248, 200, 93,	 24,  249, 138, 33,  80,  188, 155, 201,
			  175, 93,  32,	 107, 130, 188, 4,   167, 155, 219},
		   32),
	       "hash");

	bible_destroy(b);
	munmap(bible, BIBLE_UNCOMPRESSED_SIZE);
}

Test(bible_store_fail) {
	if (IS_VALGRIND()) return;
	const Bible *bible = bible_load(BIBLE_PATH);
	_debug_pwrite_fail = 0;
	ASSERT_EQ(bible_store(bible, "/tmp/bible_err"), -1, "pwrite_fail");
	_debug_pwrite_fail = I64_MAX;
	bible_destroy(bible);
}

