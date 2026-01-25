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
#include <libfam/utils.h>

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

