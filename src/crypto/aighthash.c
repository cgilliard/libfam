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

#include <libfam/aesenc.h>
#include <libfam/aighthash.h>
#include <libfam/string.h>
#include <libfam/utils.h>

#ifndef NO_VECTOR
#ifdef __AVX2__
#define USE_AVX2
#elif defined(__ARM_FEATURE_CRYPTO)
#define USE_NEON
#endif /* __ARM_FEATURE_CRYPTO */
#endif /* NO_VECTOR */

#ifdef USE_NEON
#include <arm_neon.h>
#endif /* USE_NEON */
#ifdef USE_AVX2
#include <immintrin.h>
#endif /* USE_AVX2 */

#ifdef __VAES__
#define AESENC256(result, data, key) \
	*(__m256i *)result =         \
	    _mm256_aesenc_epi128(*(__m256i *)data, *(__m256i *)key);
#else
#define AESENC256(result, data, key)                                           \
	do {                                                                   \
		__m128i data_lo = _mm256_castsi256_si128(*(__m256i *)data);    \
		__m128i data_hi =                                              \
		    _mm256_extracti128_si256(*(__m256i *)data, 1);             \
                                                                               \
		__m128i key_lo = _mm256_castsi256_si128(*(__m256i *)key);      \
		__m128i key_hi = _mm256_extracti128_si256(*(__m256i *)key, 1); \
                                                                               \
		data_lo = _mm_aesenc_si128(data_lo, key_lo);                   \
		data_hi = _mm_aesenc_si128(data_hi, key_hi);                   \
		fastmemcpy(result, &data_lo, 16);                              \
		fastmemcpy((u8 *)result + 16, &data_hi, 16);                   \
	} while (0);
#endif /* !__VAES__ */

static const __attribute__((aligned(32))) u128 AIGHT_NUMS[] = {
    ((u128)0xa70413383f55618fULL << 64) | 0x376d0932e21de58fULL,
    ((u128)0xf95524bf9f2fdfa8ULL << 64) | 0xf3fb6d8bd7643b1dULL,
};
static const u8 *AIGHT_DOMAIN = (void *)AIGHT_NUMS;

#define AIGHT64_INIT 0x9E3779B97F4A7C15ULL
#define AIGHT_P1 0xc2b2ae35u
#define AIGHT_P2 0x85ebca6bu

PUBLIC u64 aighthash64(const void *data, u64 len, u64 seed) {
	const u8 *p = (const u8 *)data;
	u64 h = seed ^ AIGHT64_INIT, tail = 0;

#ifdef USE_AVX2
	__m256i key = _mm256_load_si256((const __m256i *)AIGHT_DOMAIN);
#elif defined(USE_NEON)
	uint8x16_t key_lo = vld1q_u8(AIGHT_DOMAIN);
	uint8x16_t key_hi = vld1q_u8(AIGHT_DOMAIN + 16);
#else
	const u8 *key = AIGHT_DOMAIN;
#endif

	while (len >= 256) {
		for (int i = 0; i < 8; i++) {
#ifdef USE_AVX2
			__m256i x =
			    _mm256_loadu_si256((const __m256i *)(p + i * 32));
			AESENC256(&x, &x, &key);

			__attribute__((aligned(32))) u64 parts[4];
			_mm256_store_si256((__m256i *)parts, x);
			h ^= parts[0] ^ parts[1] ^ parts[2] ^ parts[3];
#elif defined(USE_NEON)
			uint8x16_t lo = vld1q_u8(p + i * 32);
			uint8x16_t hi = vld1q_u8(p + i * 32 + 16);

			lo = veorq_u8(lo, key_lo);
			lo = vaeseq_u8(lo, vdupq_n_u8(0));
			lo = vaesmcq_u8(lo);

			hi = veorq_u8(hi, key_hi);
			hi = vaeseq_u8(hi, vdupq_n_u8(0));
			hi = vaesmcq_u8(hi);

			__attribute__((aligned(16))) u64 parts[4];
			vst1q_u64(parts + 0, vreinterpretq_u64_u8(lo));
			vst1q_u64(parts + 2, vreinterpretq_u64_u8(hi));

			h ^= parts[0] ^ parts[1] ^ parts[2] ^ parts[3];
#else
			u8 x[32];
			fastmemcpy(x, p + i * 32, 32);
			aesenc256(x, key);
			h ^= *(u64 *)x ^ *(u64 *)(x + 8) ^ *(u64 *)(x + 16) ^
			     *(u64 *)(x + 24);
#endif
		}
		p += 256;
		len -= 256;
	}

	while (len >= 32) {
#ifdef USE_AVX2
		__m256i x = _mm256_loadu_si256((const __m256i *)p);
		AESENC256(&x, &x, &key);

		__attribute__((aligned(32))) u64 parts[4];
		_mm256_store_si256((__m256i *)parts, x);
		h ^= parts[0] ^ parts[1] ^ parts[2] ^ parts[3];
#elif defined(USE_NEON)
		uint8x16_t lo = vld1q_u8(p);
		uint8x16_t hi = vld1q_u8(p + 16);

		lo = veorq_u8(lo, key_lo);
		lo = vaeseq_u8(lo, vdupq_n_u8(0));
		lo = vaesmcq_u8(lo);

		hi = veorq_u8(hi, key_hi);
		hi = vaeseq_u8(hi, vdupq_n_u8(0));
		hi = vaesmcq_u8(hi);

		__attribute__((aligned(16))) u64 parts[4];
		vst1q_u64(parts + 0, vreinterpretq_u64_u8(lo));
		vst1q_u64(parts + 2, vreinterpretq_u64_u8(hi));

		h ^= parts[0] ^ parts[1] ^ parts[2] ^ parts[3];
#else
		u8 x[32];
		fastmemcpy(x, p, 32);
		aesenc256(x, key);
		h ^= *(u64 *)x ^ *(u64 *)(x + 8) ^ *(u64 *)(x + 16) ^
		     *(u64 *)(x + 24);
#endif
		p += 32;
		len -= 32;
	}

	while (len--) tail ^= (u64)*p++ << (8 * (len & 7));

	h ^= tail;
	h *= AIGHT_P2;
	h ^= h >> 29;
	h *= AIGHT_P1;
	h ^= h >> 33;

	return h;
}
