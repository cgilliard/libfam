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

#include <libfam/compress.h>
#include <libfam/linux.h>
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
