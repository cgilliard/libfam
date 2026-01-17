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

#ifndef _AESENC_H
#define _AESENC_H

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

void aesenc256(void *data, const void *key);

#endif /* _AESENC_H */
