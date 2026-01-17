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

#include <libfam/storm.h>
#include <libfam/string.h>
#include <libfam/wots.h>

#define WOTS_W 256
#define WOTS_N 32
#define WOTS_LEN1 16
#define WOTS_LEN2 2
#define WOTS_LEN (WOTS_LEN1 + WOTS_LEN2)

__attribute__((aligned(32))) static const u8 DOMAIN_CHAIN[32] = {
    0x01, 'W', 'O', 'T', 'S', '+', 'c', 'h', 'a', 'i', 'n'};

static void wots_chain(StormContext *ctx, u8 out[32], const u8 in[32],
		       u32 steps) {
	fastmemcpy(out, in, 32);

	for (u32 i = 0; i < steps; ++i) {
		storm_init(ctx, DOMAIN_CHAIN);
		storm_next_block(ctx, out);
	}
}

void wots_keyfrom(const u8 seed[32], WotsPubKey *pk, WotsSecKey *sk) {
	StormContext ctx;
	storm_init(&ctx, seed);
	fastmemset(sk->data, 0, WOTS_SECKEY_SIZE);

	for (u32 i = 0; i < WOTS_LEN; ++i)
		storm_next_block(&ctx, sk->data + i * WOTS_N);

	for (u32 i = 0; i < WOTS_LEN; ++i) {
		const u8 *base = sk->data + i * WOTS_N;
		wots_chain(&ctx, pk->data + i * WOTS_N, base, WOTS_W - 1);
	}
	secure_zero(&ctx, sizeof(ctx));
}

void wots_sign(const WotsSecKey *sk, const u8 message[32], WotsSig *sig) {
	StormContext ctx;
	u16 checksum = 0;

	for (u32 i = 0; i < WOTS_LEN1; ++i) {
		u8 digit = message[i] ^ message[i + WOTS_LEN1];
		checksum += (WOTS_W - 1) - digit;
		u32 steps = digit;
		wots_chain(&ctx, sig->data + i * WOTS_N, sk->data + i * WOTS_N,
			   steps);
	}

	for (u32 i = 0; i < WOTS_LEN2; ++i) {
		u8 digit = (checksum >> (8 * i)) & 0xFF;
		u32 steps = digit;
		u32 chain_idx = WOTS_LEN1 + i;
		wots_chain(&ctx, sig->data + chain_idx * WOTS_N,
			   sk->data + chain_idx * WOTS_N, steps);
	}

	secure_zero(&ctx, sizeof(ctx));
}

i32 wots_verify(const WotsPubKey *pk, const WotsSig *sig,
		const u8 message[32]) {
	StormContext ctx;
	u16 checksum = 0;
	__attribute__((aligned(32))) u8 tmp[32];
	i32 ret = 0;

	for (u32 i = 0; i < WOTS_LEN1; ++i) {
		u8 digit = message[i] ^ message[i + WOTS_LEN1];
		checksum += (WOTS_W - 1) - digit;
		u32 steps = (WOTS_W - 1) - digit;
		const u8 *revealed = sig->data + i * WOTS_N;
		wots_chain(&ctx, tmp, revealed, steps);
		if (fastmemcmp(tmp, pk->data + i * WOTS_N, WOTS_N) != 0)
			ret = -1;
	}

	for (u32 i = 0; i < WOTS_LEN2; ++i) {
		u8 expected_digit = (checksum >> (8 * i)) & 0xFF;
		u32 steps = (WOTS_W - 1) - expected_digit;
		u32 chain_idx = WOTS_LEN1 + i;
		const u8 *revealed = sig->data + chain_idx * WOTS_N;
		wots_chain(&ctx, tmp, revealed, steps);
		if (fastmemcmp(tmp, pk->data + chain_idx * WOTS_N, WOTS_N) != 0)
			ret = -1;
	}

	return ret;
}
