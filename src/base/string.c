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

#include <libfam/limits.h>
#include <libfam/string.h>
#include <libfam/types.h>
#include <libfam/utils.h>

#ifndef NO_VECTOR
#ifdef __AVX2__
#define USE_AVX2
#endif /* __AVX2__ */
#endif /* NO_VECTOR */

#ifdef USE_AVX2
#include <immintrin.h>
#endif /* USE_AVX2 */

PUBLIC u64 strlen(const char *x) {
	const char *y = x;
	while (*x) x++;
	return x - y;
}

PUBLIC i32 strcmp(const char *x, const char *y) {
	while (*x == *y && *x) x++, y++;
	return *x > *y ? 1 : *y > *x ? -1 : 0;
}

PUBLIC char *strcpy(char *dest, const char *src) {
	char *ptr = dest;
	while ((*ptr++ = *src++));
	return dest;
}

PUBLIC char *strncpy(char *dest, const char *src, u64 n) {
	u64 i;
	for (i = 0; i < n && src[i] != '\0'; i++) dest[i] = src[i];
	for (; i < n; i++) dest[i] = '\0';
	return dest;
}

PUBLIC char *strcat(char *dest, const char *src) {
	char *ptr = dest;
	while (*ptr) ptr++;
	while ((*ptr++ = *src++));
	return dest;
}

PUBLIC char *strchr(const char *s, i32 c) {
	do
		if (*s == c) return (char *)s;
	while (*s++);
	return !c ? (char *)s : NULL;
}

PUBLIC i32 strncmp(const char *x, const char *y, u64 n) {
	while (n > 0 && *x == *y && *x) x++, y++, n--;
	if (n == 0) return 0;
	return (char)*x - (char)*y;
}

PUBLIC void *memset(void *dest, i32 c, u64 n) {
	u8 *tmp = dest;
	while (n--) *tmp++ = (char)c;
	return dest;
}

PUBLIC void *memcpy(void *dest, const void *src, u64 n) {
	u8 *d = (u8 *)dest;
	const u8 *s = (void *)src;
	while (n--) *d++ = *s++;
	return dest;
}

PUBLIC i32 memcmp(const void *s1, const void *s2, u64 n) {
	const u8 *p1 = (void *)s1;
	const u8 *p2 = (void *)s2;
	while (n--) {
		i32 diff = *p1++ - *p2++;
		if (diff) return diff;
	}
	return 0;
}

PUBLIC void *memmove(void *dest, const void *src, u64 n) {
	u8 *d = (void *)((u8 *)dest + n);
	u8 *s = (void *)((u8 *)src + n);
	while (n--) d--, s--, *d = *s;
	return dest;
}

PUBLIC u8 f64_to_string(u8 buf[MAX_F64_STRING_LEN], f64 v, i32 max_decimals,
			bool commas) {
	u64 pos = 0;
	i32 is_negative;
	u64 int_part;
	f64 frac_part;
	i32 i;
	u8 temp[MAX_F64_STRING_LEN];

	if (v != v) {
		buf[0] = 'n';
		buf[1] = 'a';
		buf[2] = 'n';
		buf[3] = '\0';
		return 3;
	}

	if (v > 1.7976931348623157e308 || v < -1.7976931348623157e308) {
		if (v < 0) buf[pos++] = '-';
		buf[pos++] = 'i';
		buf[pos++] = 'n';
		buf[pos++] = 'f';
		buf[pos] = '\0';
		return pos;
	}

	is_negative = v < 0;
	if (is_negative) {
		buf[pos++] = '-';
		v = -v;
	}

	if (v == 0.0) {
		buf[pos++] = '0';
		buf[pos] = '\0';
		return pos;
	}

	if (max_decimals < 0) max_decimals = 0;
	if (max_decimals > 17) max_decimals = 17;

	int_part = (u64)v;
	frac_part = v - (f64)int_part;

	if (max_decimals > 0) {
		f64 rounding = 0.5;
		for (i = 0; i < max_decimals; i++) rounding /= 10.0;
		v += rounding;
		int_part = (u64)v;
		frac_part = v - (f64)int_part;
	}

	if (int_part == 0)
		buf[pos++] = '0';
	else {
		i = 0;
		while (int_part > 0) {
			temp[i++] = '0' + (int_part % 10);
			int_part /= 10;
		}
		if (commas) {
			u64 digit_count = i;
			u64 digits_until_comma =
			    digit_count % 3 ? digit_count % 3 : 3;
			i--;
			while (i >= 0) {
				buf[pos++] = temp[i--];
				digits_until_comma--;
				if (digits_until_comma == 0 && i >= 0) {
					buf[pos++] = ',';
					digits_until_comma = 3;
				}
			}
		} else
			while (i > 0) buf[pos++] = temp[--i];
	}

	if (frac_part > 0 && max_decimals > 0) {
		buf[pos++] = '.';
		u64 frac_start = pos;
		i32 digits = 0;
		while (digits < max_decimals) {
			frac_part *= 10;
			i32 digit = (i32)frac_part;
			buf[pos++] = '0' + digit;
			frac_part -= digit;
			digits++;
		}
		while (pos > frac_start && buf[pos - 1] == '0') pos--;
		if (pos == frac_start) pos--;
	}

	buf[pos] = '\0';
	return pos;
}

PUBLIC void secure_zero32(u8 buf[32]) {
#ifdef USE_AVX2
	__m256i zero = _mm256_setzero_si256();
	_mm256_store_si256((__m256i *)buf, zero);
	__asm__ __volatile__("" ::: "memory");
#else
	secure_zero(buf, 32);
#endif /* !USE_AVX2 */
}

PUBLIC i32 string_to_u128(const u8 *buf, u64 len, u128 *result) {
	u64 i = 0;
	u8 c;

	*result = 0;
	if (!buf || !len) ERR(EINVAL);
	while (i < len && (buf[i] == ' ' || buf[i] == '\t')) i++;
	if (i == len) ERR(EINVAL);
	while (i < len) {
		c = buf[i];
		if (c < '0' || c > '9') ERR(EINVAL);
		if (*result > U128_MAX / 10) ERR(EOVERFLOW);
		*result = *result * 10 + (c - '0');
		i++;
	}
	return 0;
}

PUBLIC u8 i128_to_string(u8 buf[MAX_I128_STRING_LEN], i128 value,
			 Int128DisplayType t) {
	u8 len;
	u128 abs_v;
	bool is_negative = value < 0;
	if (is_negative) {
		*buf++ = '-';
		abs_v = value == I128_MIN ? (u128)1 << 127 : (u128)(-value);
	} else
		abs_v = (u128)value;
	len = u128_to_string(buf, abs_v, t);
	return len < 0 ? len : is_negative ? len + 1 : len;
}

PUBLIC u8 u128_to_string(u8 buf[MAX_U128_STRING_LEN], u128 value,
			 Int128DisplayType t) {
	u8 temp[MAX_U128_STRING_LEN];
	i32 i = 0, j = 0;
	bool hex =
	    t == Int128DisplayTypeHexUpper || t == Int128DisplayTypeHexLower;
	bool commas = t == Int128DisplayTypeCommas;
	u8 mod_val =
	    hex ? 16 : (commas || t == Int128DisplayTypeDecimal ? 10 : 2);
	const u8 *hex_code = t == Int128DisplayTypeHexUpper
				 ? "0123456789ABCDEF"
				 : "0123456789abcdef";
	if (hex) {
		j = 2;
		buf[0] = '0';
		buf[1] = 'x';
	}
	if (value == 0) {
		buf[j++] = '0';
		buf[j] = '\0';
		return j;
	}
	while (value > 0) {
		temp[i++] = hex_code[(value % mod_val)];
		if (mod_val == 16)
			value >>= 4;
		else if (mod_val == 10)
			value /= 10;
		else if (mod_val == 2)
			value >>= 1;
	}
	if (commas) {
		u64 digit_count = i;
		u64 comma_count = digit_count > 3 ? (digit_count - 1) / 3 : 0;
		u64 total_bytes = digit_count + comma_count;
		j = 0;
		i--;
		u64 digits_until_comma = digit_count % 3 ? digit_count % 3 : 3;
		while (i >= 0) {
			buf[j++] = temp[i--];
			digits_until_comma--;
			if (digits_until_comma == 0 && i >= 0) {
				buf[j++] = ',';
				digits_until_comma = 3;
			}
		}
		buf[j] = '\0';
		return total_bytes;
	} else {
		for (; i > 0; j++) {
			buf[j] = temp[--i];
		}
		buf[j] = '\0';
		return j;
	}
}

PUBLIC char *strstr(const char *s, const char *sub) {
	for (; *s; s++) {
		const u8 *tmps = s, *tmpsub = sub;
		while (*tmps == *tmpsub && *tmps) tmps++, tmpsub++;
		if (*tmpsub == '\0') return (u8 *)s;
	}
	return NULL;
}

