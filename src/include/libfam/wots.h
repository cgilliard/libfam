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

#ifndef _WOTS_H
#define _WOTS_H

#include <libfam/types.h>

#define WOTS_CHAINS 18
#define WOTS_CHAIN_LEN 256
#define WOTS_HASH_BYTES 32

#define WOTS_SECKEY_SIZE (WOTS_CHAINS * WOTS_HASH_BYTES)
#define WOTS_PUBKEY_SIZE (WOTS_CHAINS * WOTS_HASH_BYTES)
#define WOTS_SIG_SIZE (WOTS_CHAINS * WOTS_HASH_BYTES)

typedef struct {
	__attribute__((aligned(32))) u8 data[WOTS_SECKEY_SIZE];
} WotsSecKey;

typedef struct {
	__attribute__((aligned(32))) u8 data[WOTS_PUBKEY_SIZE];
} WotsPubKey;

typedef struct {
	__attribute__((aligned(32))) u8 data[WOTS_SIG_SIZE];
} WotsSig;

void wots_keyfrom(const u8 seed[32], WotsPubKey *pk, WotsSecKey *sk);
void wots_sign(const WotsSecKey *sk, const u8 message[32], WotsSig *sig);
i32 wots_verify(const WotsPubKey *pk, const WotsSig *sig, const u8 message[32]);

#endif /* _WOTS_H */
