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
#include <libfam/builtin.h>
#include <libfam/compress.h>
#include <libfam/env.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/storm.h>
#include <libfam/test.h>

Test(compress1) {
	u8 out[10000] = {0};
	u8 in[256 + 32 + 20] = "abcdefgabcd11223344455667788";
	u8 verify[3000] = {0};
	i32 res = compress_block(in, sizeof(in), out, sizeof(out));
	res = decompress_block(out, res, verify, sizeof(verify));
	ASSERT_EQ(res, sizeof(in), "size");
	ASSERT(!memcmp(in, verify, sizeof(in)), "verify");
}

Test(compress2) {
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

Test(compressfile_fails) {
	const u8 *path = "./resources/akjv5.txt";
	const u8 *outpath = "/tmp/akjv5.txt.tmp";
	const u8 *outpath2 = "/tmp/akjv5.txt.conf";
	unlink(outpath);
	unlink(outpath2);

	i32 infd = open(path, O_RDONLY, 0);
	i32 outfd = open(outpath, O_CREAT | O_RDWR, 0600);

	_debug_fork_fail = true;
	i32 res = compress_file(infd, 0, outfd, 0);
	if (get_physical_cores_cpuid() == 1) res = -1;	// simulate for 1 core

	ASSERT_EQ(res, -1, "compress_file fail");
	ASSERT_EQ(decompress_file(infd, 0, outfd, 0), -1,
		  "decompress_file fail");
	_debug_fork_fail = false;

	_debug_pwrite_fail = 0;
	ASSERT_EQ(decompress_file(infd, 0, outfd, 0), -1,
		  "decompress_file fail2");
	_debug_pwrite_fail = I64_MAX;

	_debug_pread_fail = 0;
	ASSERT_EQ(decompress_file(infd, 0, outfd, 0), -1,
		  "decompress_file fail3");
	_debug_pread_fail = I64_MAX;

	close(infd);
	close(outfd);
}

Test(compressfile_fails2) {
	const u8 *path = "./resources/xxdir/akjv.txt.cz";
	const u8 *outpath = "/tmp/akjv5.txt.tmp";
	const u8 *outpath2 = "/tmp/akjv5.txt.conf";
	unlink(outpath);
	unlink(outpath2);

	i32 infd = open(path, O_RDONLY, 0);
	i32 outfd = open(outpath, O_CREAT | O_RDWR, 0600);

	_debug_pwrite_fail = 0;
	ASSERT_EQ(compress_file(infd, 0, outfd, 0), -1, "compress_file fail");
	_debug_pwrite_fail = I64_MAX;

	_debug_pread_fail = 0;
	ASSERT_EQ(compress_file(infd, 0, outfd, 0), -1, "compress_file fail2");
	_debug_pread_fail = I64_MAX;

	close(infd);
	close(outfd);
}

Test(decompressfile_fails) {
	const u8 *path = "./resources/akjv5.txt";
	const u8 *outpath = "/tmp/akjv5.txt.tmp";
	const u8 *outpath2 = "/tmp/akjv5.txt.conf";
	unlink(outpath);
	unlink(outpath2);

	i32 infd = open(path, O_RDONLY, 0);
	i32 outfd = open(outpath, O_CREAT | O_RDWR, 0600);
	errno = 0;
	i32 res = compress_file(infd, 0, outfd, 0);
	ASSERT(!res, "compress_file");
	close(infd);
	close(outfd);

	infd = open(outpath, O_RDONLY, 0);
	outfd = open(outpath2, O_CREAT | O_RDWR, 0600);

	for (u32 i = 0; i < 100; i++) {
		_debug_pread_fail = i;
		ASSERT_EQ(decompress_file(infd, 0, outfd, 0), -1,
			  "decomp file fail1");
		_debug_pread_fail = I64_MAX;
	}

	for (u32 i = 0; i < 10; i++) {
		_debug_pwrite_fail = i;
		ASSERT_EQ(decompress_file(infd, 0, outfd, 0), -1,
			  "decomp file fail2");
		_debug_pwrite_fail = I64_MAX;
	}

	for (u32 i = 0; i < 10; i++) {
		_debug_pwrite_fail = i;
		ASSERT_EQ(compress_stream(infd, 0, outfd, 0), -1,
			  "decomp file fail3");
		_debug_pwrite_fail = I64_MAX;
		_debug_pwrite_fail = i;
		ASSERT_EQ(decompress_stream(infd, 0, outfd, 0), -1,
			  "decomp file fail3");
		_debug_pwrite_fail = I64_MAX;
	}

	_debug_compress_fail = true;
	ASSERT_EQ(decompress_file(infd, 0, outfd, 0), -1,
		  "decomp file fail comp fail");
	_debug_compress_fail = false;

	_debug_compress_fail = true;
	ASSERT_EQ(compress_file(infd, 0, outfd, 0), -1,
		  "decomp file fail comp fail");
	_debug_compress_fail = false;

	close(infd);
	close(outfd);
}

Test(compressfile1) {
	const u8 *path = "./resources/akjv5.txt";
	const u8 *outpath = "/tmp/akjv5.txt.tmp";
	const u8 *outpath2 = "/tmp/akjv5.txt.conf";
	unlink(outpath);
	unlink(outpath2);

	i64 timer = micros();
	i32 infd = open(path, O_RDONLY, 0);
	i32 outfd = open(outpath, O_CREAT | O_RDWR, 0600);
	ASSERT(!compress_file(infd, 0, outfd, 0), "compress_file");
	u64 insize = fsize(outfd);
	u64 outsize = fsize(infd);
	close(infd);
	close(outfd);
	timer = micros() - timer;

	timer = micros();
	infd = open(outpath, O_RDONLY, 0);
	outfd = open(outpath2, O_CREAT | O_RDWR, 0600);
	decompress_file(infd, 0, outfd, 0);
	close(infd);
	close(outfd);
	timer = micros() - timer;

	(void)insize;
	(void)outsize;

	i32 fd1 = open(outpath2, O_RDWR, 0);
	i32 fd2 = open(path, O_RDWR, 0);

	ASSERT_EQ(fsize(fd1), fsize(fd2), "fsize");

	void *ptr1 = fmap(fd1, fsize(fd1), 0);
	void *ptr2 = fmap(fd2, fsize(fd2), 0);

	ASSERT(!memcmp(ptr1, ptr2, fsize(fd1)), "equal");

	munmap(ptr1, fsize(fd1));
	munmap(ptr2, fsize(fd2));
	close(fd1);
	close(fd2);

	ASSERT_BYTES(0);
}

Test(compress_raw) {
	u8 in[1024] = {'a', 'b', 'c'}, out[1024] = {0}, verify[1024] = {0};
	ASSERT_EQ(compress_block(in, 3, out, 6), 6, "compress3");
	i32 x = decompress_block(out, 6, verify, sizeof(verify));
	ASSERT_EQ(x, 3, "decompress3");
	ASSERT(!memcmp(verify, (u8[]){'a', 'b', 'c'}, 3), "verify");

	ASSERT_EQ(compress_block(in, 0, out, 3), 3, "compress0");
	ASSERT_EQ(decompress_block(out, 3, verify, 0), 0, "verify0");

	verify[0] = 'x';
	ASSERT_EQ(compress_block(in, 1, out, 4), 4, "compress1");
	ASSERT_EQ(decompress_block(out, 4, verify, 1), 1, "verify1");
	ASSERT_EQ(verify[0], 'a', "a");
}

Test(compress_stream) {
	const u8 *path1 = "./resources/akjv5.txt";
	const u8 *path_out1 = "/tmp/compress_stream1.out";
	const u8 *path_out2 = "/tmp/compress_stream2.out";
	unlink(path_out1);
	unlink(path_out2);
	i32 fd1 = open(path1, O_RDONLY, 0);
	i32 fd2 = open(path_out1, O_CREAT | O_RDWR, 0600);

	ASSERT(!compress_stream(fd1, 0, fd2, 0), "compress_stream");
	close(fd1);
	close(fd2);

	fd1 = open(path_out1, O_RDONLY, 0);
	fd2 = open(path_out2, O_CREAT | O_RDWR, 0600);

	ASSERT(!decompress_stream(fd1, 0, fd2, 0), "decompress_stream");
	close(fd1);
	close(fd2);
}

i32 compress_read_raw(const u8 *in, u32 len, u8 *out, u32 capacity);
i32 compress_read_block(const u8 *in, u32 len, u8 *out, u32 capacity);

Test(compress_errors) {
	ASSERT_EQ(compress_block(NULL, 0, NULL, 0), -1, "null input");
	ASSERT_EQ(decompress_block(NULL, 0, NULL, 0), -1, "null input");
	ASSERT_EQ(decompress_block("", 0, "", 0), -1, "short");
	ASSERT_EQ(compress_block("", 0, "", 0), -1, "bound");
	ASSERT_EQ(compress_read_raw(NULL, 0, NULL, 0), -1, "raw");
	ASSERT_EQ(compress_read_raw("xxx", 3, NULL, 0), -1, "invalid");
	ASSERT_EQ(compress_read_raw("xxxx", 4, NULL, 0), -1, "invalid");
	ASSERT_EQ(compress_read_raw("xxxx", 4, NULL, U32_MAX), -1, "invalid");
	ASSERT_EQ(compress_read_block("", 0, NULL, 0), -1,
		  "invalid read block");

	const u8 *path = "./resources/test_wikipedia.txt";
	i32 fd = open(path, O_RDWR, 0);
	u32 size = fsize(fd);
	u8 *in = fmap(fd, size, 0);
	u8 out[100000] = {0}, verify[100000] = {0};
	i32 res = compress_block(in, size, out, sizeof(out));
	for (u32 i = 0; i < 1000; i++)
		ASSERT_EQ(compress_read_block(out, res, verify, i), -1,
			  "overflow");

	munmap(in, size);
	close(fd);

	ASSERT_EQ(compress_file(0, 0, 0, 0), -1, "err compress_file");
	ASSERT_EQ(decompress_file(0, 0, 0, 0), -1, "err decompress_file");

	_debug_alloc_count = 0;
	ASSERT_EQ(decompress_file(0, 0, 0, 0), -1, "err decompress_file");
	_debug_alloc_count = I64_MAX;

	_debug_fail_fstat = true;
	ASSERT_EQ(decompress_file(0, 0, 0, 0), -1, "err decompress_file");
	_debug_fail_fstat = false;

	fd = open(path, O_RDONLY, 0);
	i32 outfd = open("/tmp/compress_err_out.txt", O_CREAT | O_RDWR, 0600);

	_debug_alloc_count = 1;
	res = decompress_file(fd, 0, outfd, 0);
	_debug_alloc_count = I64_MAX;
	close(fd);
	close(outfd);
	ASSERT_EQ(res, -1, "decomp err");
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
		fastmemcpy(buffer, bible + off, 32);
		storm_next_block(&ctx, buffer);
		off += 32;
	}

	const u8 *check =
	    "Genesis||1||1||In the beginning God created the heaven "
	    "and the "
	    "earth.";

	ASSERT(!memcmp(bible, check, strlen(check)), "first verse");
	ASSERT(!memcmp(buffer, (u8[]){40,  57,	160, 40,  170, 236, 126, 115,
				      174, 135, 8,   248, 200, 93,  24,	 249,
				      138, 33,	80,  188, 155, 201, 175, 93,
				      32,  107, 130, 188, 4,   167, 155, 219},
		       32),
	       "hash");

	bible_destroy(b);
	munmap(bible, BIBLE_UNCOMPRESSED_SIZE);
}
