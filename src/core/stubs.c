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

#include <libfam/builtin.h>
#include <libfam/types.h>
#include <libfam/utils.h>

typedef union {
	u128 all;
	struct {
		u64 low;
		u64 high;
	} s;
} utwords;

static inline u64 udiv128by64to64(u64 u1, u64 u0, u64 v, u64 *r) {
	const unsigned n_udword_bits = sizeof(u64) * 8;
	const u64 b = (1ULL << (n_udword_bits / 2));  // Number base (32 bits)
	u64 un1, un0;				      // Norm. dividend LSD's
	u64 vn1, vn0;				      // Norm. divisor digits
	u64 q1, q0;				      // Quotient digits
	u64 un64, un21, un10;			      // Dividend digit pairs
	u64 rhat;				      // A remainder
	i32 s;	// Shift amount for normalization

	s = clz_u64(v);
	if (s > 0) {
		// Normalize the divisor.
		v = v << s;
		un64 = (u1 << s) | (u0 >> (n_udword_bits - s));
		un10 = u0 << s;	 // Shift dividend left
	} else {
		// Avoid undefined behavior of (u0 >> 64).
		un64 = u1;
		un10 = u0;
	}

	// Break divisor up into two 32-bit digits.
	vn1 = v >> (n_udword_bits / 2);
	vn0 = v & 0xFFFFFFFF;

	un1 = un10 >> (n_udword_bits / 2);
	un0 = un10 & 0xFFFFFFFF;

	q1 = un64 / vn1;
	rhat = un64 - q1 * vn1;

	while (q1 >= b || q1 * vn0 > b * rhat + un1) {
		q1 = q1 - 1;
		rhat = rhat + vn1;
		if (rhat >= b) break;
	}

	un21 = un64 * b + un1 - q1 * v;

	q0 = un21 / vn1;
	rhat = un21 - q0 * vn1;

	while (q0 >= b || q0 * vn0 > b * rhat + un0) {
		q0 = q0 - 1;
		rhat = rhat + vn1;
		if (rhat >= b) break;
	}

	*r = (un21 * b + un0 - q0 * v) >> s;
	return q1 * b + q0;
}

u128 __udivmodti4(u128 a, u128 b, u128 *rem) {
	const unsigned n_utword_bits = sizeof(u128) * 8;
	utwords dividend;
	dividend.all = a;
	utwords divisor;
	divisor.all = b;
	utwords quotient;
	utwords remainder;
	if (divisor.all > dividend.all) {
		if (rem) *rem = dividend.all;
		return 0;
	}
	if (divisor.s.high == 0) {
		remainder.s.high = 0;
		if (dividend.s.high < divisor.s.low) {
			quotient.s.low =
			    udiv128by64to64(dividend.s.high, dividend.s.low,
					    divisor.s.low, &remainder.s.low);
			quotient.s.high = 0;
		} else {
			quotient.s.high = dividend.s.high / divisor.s.low;
			dividend.s.high = dividend.s.high % divisor.s.low;
			quotient.s.low =
			    udiv128by64to64(dividend.s.high, dividend.s.low,
					    divisor.s.low, &remainder.s.low);
		}
		if (rem) *rem = remainder.all;
		return quotient.all;
	}
	i32 shift = clz_u64(divisor.s.high) - clz_u64(dividend.s.high);
	divisor.all <<= shift;
	quotient.s.high = 0;
	quotient.s.low = 0;
	for (; shift >= 0; --shift) {
		quotient.s.low <<= 1;
		const i128 s = (i128)(divisor.all - dividend.all - 1) >>
			       (n_utword_bits - 1);
		quotient.s.low |= s & 1;
		dividend.all -= divisor.all & s;
		divisor.all >>= 1;
	}
	if (rem) *rem = dividend.all;
	return quotient.all;
}

PUBLIC u128 __umodti3(u128 a, u128 b) {
	u128 r;
	__udivmodti4(a, b, &r);
	return r;
}

PUBLIC u128 __udivti3(u128 a, u128 b) { return __udivmodti4(a, b, 0); }

