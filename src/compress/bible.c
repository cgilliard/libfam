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

#ifndef NO_VECTOR
#ifdef __AVX2__
#define USE_AVX2
#endif /* __AVX2__ */
#endif /* NO_VECTOR */

#ifdef USE_AVX2
#include <immintrin.h>
#endif /* USE_AVX2 */

#include <libfam/bible.h>
#include <libfam/compress.h>
#include <libfam/fstatx.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>
#include <libfam/xxdir_dat.h>

#define WYHASH_P1 0xff51afd7ed558ccdULL
#define WYHASH_P2 0xc4ceb9fe1a85ec53ULL
#define GOLDEN_PRIME 0x517cc1b727220a95ULL
#define PHI_PRIME 0x9e3779b97f4a7c15ULL
#define LOOKUP_ROUNDS 32
#define STORM_ITER (LOOKUP_ROUNDS * 1024)

#define EXTENDED_BIBLE_SIZE (16 * 1024 * 1024)
#define BIBLE_EXTENDED_INDICES (EXTENDED_BIBLE_SIZE >> 5)
#define BIBLE_EXTENDED_MASK (BIBLE_EXTENDED_INDICES - 1)

__attribute__((aligned(32))) static const u8 BIBLE_GEN_DOMAIN[32] = {
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15, 0x85, 0xeb,
    0xca, 0x6b, 0xc2, 0xb2, 0xae, 0x35, 0x51, 0x7c, 0xc1, 0xb7,
    0x27, 0x22, 0x0a, 0x95, 0x07, 0x00, 0x00, 0x01};

__attribute__((aligned(32))) static const u8 BIBLE_SBOX_DOMAIN[32] = {
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15, 0x85, 0xeb,
    0xca, 0x6b, 0xc2, 0xb2, 0xae, 0x35, 0x51, 0x7c, 0xc1, 0xb7,
    0x27, 0x22, 0x0a, 0x95, 0x07, 0x00, 0x00, 0x02};

struct __attribute__((aligned(64))) Bible {
	u64 flags;
	u64 padding[7];
	u8 data[];
};

PUBLIC const Bible *bible_gen(bool print_status) {
	__attribute__((aligned(32))) u8 buffer[32] = {0};
	StormContext ctx;
	u64 last_percent = 0, counter = 0;
	i64 last_update = 0;

	Bible *ret = map(sizeof(Bible) + EXTENDED_BIBLE_SIZE);
	if (!ret) return NULL;
	ret->flags = 0;
	fastmemcpy(ret->data, xxdir_file_0, xxdir_file_size_0);

	storm_init(&ctx, BIBLE_GEN_DOMAIN);
	u64 off = 0;
	while (off < (xxdir_file_size_0 & ~31U)) {
		fastmemcpy(buffer, xxdir_file_0 + off, 32);
		storm_next_block(&ctx, buffer);
		off += 32;
	}

	if (print_status) pwrite(2, "\n", 1, 0);
	for (u64 offset = (xxdir_file_size_0 + 31) & ~31;
	     offset < EXTENDED_BIBLE_SIZE; offset += 32) {
		for (u32 i = 0; i < STORM_ITER; i++)
			storm_next_block(&ctx, buffer);

		fastmemcpy(ret->data + offset, buffer, 32);
		if (print_status) {
			u64 percent = offset * 100 / EXTENDED_BIBLE_SIZE;
			i64 current = micros();
			if (percent != last_percent ||
			    (current - last_update) > 500000) {
				static const u8 msg[] = "\rBible gen status: ";
				pwrite(2, msg, sizeof(msg) - 1, 0);

				write_num(2, percent);
				pwrite(2, "% ", 2, 0);

				static const u8 spinner[] = ".oOOo";
				u8 msg2[3];
				msg2[0] = spinner[counter % 5];
				msg2[1] = ' ';
				msg2[2] = ' ';
				pwrite(2, msg2, 3, 0);
				pwrite(2, "  ", 2, 0);
				counter++;

				last_percent = percent;
				last_update = current;
			}
		}
	}
	if (print_status) {
		static const u8 msg[] = "\rBible gen status: 100%   \n";
		pwrite(2, msg, sizeof(msg) - 1, 0);
	}

	return ret;
}

PUBLIC const Bible *bible_load(const u8 *path) {
	const Bible *ret = NULL;
	i32 fd = open(path, O_RDWR, 0);

	if (fd >= 0) {
		ret = fmap(fd, sizeof(Bible) + EXTENDED_BIBLE_SIZE, 0);
		close(fd);
	}

	return ret;
}

PUBLIC i32 bible_store(const Bible *bible, const u8 *path) {
	i32 ret = 0;
	i32 fd;
	u64 to_write = sizeof(Bible) + EXTENDED_BIBLE_SIZE;

	fd = open(path, O_CREAT | O_RDWR, 0600);
	if (fd < 0) return -1;
	while (to_write) {
		i64 v = pwrite(fd, bible, to_write, 0);
		if (v < 0) {
			ret = -1;
			goto cleanup;
		}
		to_write -= v;
	}

cleanup:
	if (fd >= 0) close(fd);
	return ret;
}

PUBLIC void bible_expand(const Bible *b, u8 bible[BIBLE_UNCOMPRESSED_SIZE]) {
	u64 offset = b->data[25] + 26;
	u32 blen;
	u32 boffset = 0;
	i32 i = 0;

	while (++i < 19) {
		fastmemcpy(&blen, b->data + offset, sizeof(u32));
		i32 res = decompress_block(b->data + offset + sizeof(u32), blen,
					   bible + boffset,
					   BIBLE_UNCOMPRESSED_SIZE - boffset);
		offset += blen + sizeof(u32);
		boffset += res;
	}
}

PUBLIC void bible_sbox8_64(u64 sbox[256]) {
	__attribute__((aligned(32))) u8 buf[32] = {0};
	StormContext ctx;
	storm_init(&ctx, BIBLE_SBOX_DOMAIN);

	u8 *sbox_u8 = (void *)sbox;
	for (u32 i = 0; i < 256 / 4; i++) {
		storm_next_block(&ctx, buf);
		fastmemcpy(sbox_u8 + i * 32, buf, 32);
	}
}

PUBLIC void bible_hash(const Bible *b, const u8 input[HASH_INPUT_LEN],
		       u8 out[32], const u64 sbox[256]) {
	__attribute__((aligned(32))) u64 d[4];
	__attribute__((aligned(32))) u64 s[4] = {GOLDEN_PRIME, PHI_PRIME,
						 WYHASH_P1, WYHASH_P2};

	for (u64 quarter = 0; quarter < 4; quarter++) {
		u64 r =
		    (u64)b->data +
		    (((s[0] ^ s[1] ^ s[2] ^ s[3]) & BIBLE_EXTENDED_MASK) << 5);
		const u8 *quarter_data = input + quarter * 32;
		const u8 *in = (const u8 *)d;

#ifdef USE_AVX2
		*(__m256i *)d = _mm256_load_si256((const __m256i *)r);
#else
		fastmemcpy(d, (void *)r, 32);
#endif /* !USE_AVX2 */

		d[0] ^= ((u64 *)quarter_data)[0];
		d[1] ^= ((u64 *)quarter_data)[1];
		d[2] ^= ((u64 *)quarter_data)[2];
		d[3] ^= ((u64 *)quarter_data)[3];

		for (int lane = 0; lane < 4; lane++) {
			u8 idx = in[lane] ^ in[lane + 4] ^ in[lane + 8] ^
				 in[lane + 12] ^ in[lane + 16] ^ in[lane + 20] ^
				 in[lane + 24] ^ in[lane + 28];
			s[lane] ^= sbox[idx];
		}
	}

	for (u64 i = 0; i < LOOKUP_ROUNDS; i++) {
		u64 r =
		    (u64)b->data +
		    (((s[0] ^ s[1] ^ s[2] ^ s[3]) & BIBLE_EXTENDED_MASK) << 5);
		const u8 *in = (const u8 *)d;
#ifdef USE_AVX2
		*(__m256i *)d = _mm256_load_si256((const __m256i *)r);
#else
		fastmemcpy(d, (void *)r, 32);
#endif /* !USE_AVX2 */

		for (i32 lane = 0; lane < 4; lane++) {
			u8 idx = in[lane] ^ in[lane + 4] ^ in[lane + 8] ^
				 in[lane + 12] ^ in[lane + 16] ^ in[lane + 20] ^
				 in[lane + 24] ^ in[lane + 28];

			s[lane] ^= sbox[idx];
		}
	}

#ifdef USE_AVX2
	_mm256_store_si256((__m256i *)out, *((__m256i *)s));
#else
	fastmemcpy(out, s, 32);
#endif /* !USE_AVX2 */
}

i32 mine_block(const Bible *bible, const u8 header[HASH_INPUT_LEN],
	       const u8 target[32], u8 out[32], u32 *nonce, u32 max_iter,
	       u64 sbox[256]) {
	if (max_iter == 0) return -1;
	u8 header_copy[HASH_INPUT_LEN];
	*nonce = 0;
	fastmemcpy(header_copy, header, HASH_INPUT_LEN);
	do {
		((u32 *)header_copy)[31] = *nonce;
		bible_hash(bible, header_copy, out, sbox);
	} while (memcmp(target, out, 32) < 0 && ++(*nonce) < max_iter);
	return *nonce == max_iter ? -1 : 0;
}

void bible_destroy(const Bible *b) {
	munmap((void *)b, sizeof(Bible) + EXTENDED_BIBLE_SIZE);
}
