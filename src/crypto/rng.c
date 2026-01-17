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

#include <libfam/atomic.h>
#include <libfam/env.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/rng.h>
#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

static u64 global_entropy_counter = U64_MAX / 2;

STATIC void try_fill_hardware(u8 buf[32]) {
#if defined(__x86_64__)
	u64 *p = (u64 *)buf;
	for (i32 i = 0; i < 4; ++i) {
		u64 val;
		unsigned char cf;
		__asm__ volatile(
		    "rdrand %0\n\t"
		    "setc %1"
		    : "=r"(val), "=qm"(cf)
		    :
		    : "cc");
		p[i] = val;
	}
#endif
}

STATIC void random32(u8 out[32]) {
	__attribute__((aligned(32))) u8 tmp[32];
	u64 *x = (u64 *)tmp;
	StormContext ctx;
	struct timespec ts;
	u64 pid;
	i32 res;

	pid = getpid();
	res = clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	if (res != 0) clock_gettime(CLOCK_MONOTONIC, &ts);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-address"
	x[0] = (u64)__builtin_return_address(1) ^ (u64)&tmp;
#pragma GCC diagnostic pop
	x[1] = (u64)ts.tv_nsec ^ (u64)&res;
	x[2] = __aadd64(&global_entropy_counter, 1) ^ (u64)&ts;
	x[3] = cycle_counter() ^ pid;

	storm_init(&ctx, tmp);
	storm_next_block(&ctx, out);

	secure_zero32(tmp);
	secure_zero(&ctx, sizeof(ctx));
}

STATIC void random_stir(u8 current[32]) {
	StormContext ctx;
	__attribute__((aligned(32))) u8 stir_in[32];
#if TEST == 1
	if (IS_VALGRIND()) fastmemset(stir_in, 0, 32);
#endif /* TEST */

	try_fill_hardware(stir_in);
	storm_init(&ctx, stir_in);
	storm_next_block(&ctx, current);
	secure_zero(&ctx, sizeof(ctx));
	secure_zero(stir_in, sizeof(stir_in));
}

PUBLIC void rng_init(Rng *rng) {
	__attribute__((aligned(32))) u8 key[32];

#if TEST == 1
	if (IS_VALGRIND()) fastmemset(key, 0, 32);
#endif /* TEST */

	random32(key);
	random_stir(key);
	storm_init(&rng->ctx, key);
	secure_zero32(key);
}

PUBLIC void rng_gen(Rng *rng, void *v, u64 size) {
	u8 *out = v;
	u64 off = 0;
	while (off + 32 <= size) {
		storm_next_block(&rng->ctx, out + off);
		off += 32;
	}

	if (off < size) {
		__attribute__((aligned(32))) u8 buf[32];

#if TEST == 1
		if (IS_VALGRIND()) fastmemset(buf, 0, 32);
#endif /* TEST */

		fastmemcpy(buf, out, size - off);
		storm_next_block(&rng->ctx, buf);
		fastmemcpy(out + off, buf, size - off);
		secure_zero32(buf);
	}
}

#if TEST == 1
void rng_test_seed(Rng *rng, u8 key[32]) { storm_init(&rng->ctx, key); }
#endif /* TEST */

