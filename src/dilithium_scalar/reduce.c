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

#ifndef USE_AVX2

#include <dilithium_scalar/params.h>
#include <dilithium_scalar/reduce.h>

/*************************************************
 * Name:        montgomery_reduce
 *
 * Description: For finite field element a with -2^{31}Q <= a <= Q*2^31,
 *              compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
 *
 * Arguments:   - i64: finite field element a
 *
 * Returns r.
 **************************************************/
i32 montgomery_reduce(i64 a) {
	i32 t;

	t = (i64)(i32)a * QINV;
	t = (a - (i64)t * Q) >> 32;
	return t;
}

/*************************************************
 * Name:        reduce32
 *
 * Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
 *              compute r \equiv a (mod Q) such that -6283008 <= r <= 6283008.
 *
 * Arguments:   - i32: finite field element a
 *
 * Returns r.
 **************************************************/
i32 reduce32(i32 a) {
	i32 t;

	t = (a + (1 << 22)) >> 23;
	t = a - t * Q;
	return t;
}

/*************************************************
 * Name:        caddq
 *
 * Description: Add Q if input coefficient is negative.
 *
 * Arguments:   - i32: finite field element a
 *
 * Returns r.
 **************************************************/
i32 caddq(i32 a) {
	a += (a >> 31) & Q;
	return a;
}

#endif /* !USE_AVX2 */
