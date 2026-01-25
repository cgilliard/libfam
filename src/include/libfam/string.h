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

#ifndef _STRING_H
#define _STRING_H

#include <libfam/types.h>

#define MAX_U128_STRING_LEN 255
#define MAX_I128_STRING_LEN (MAX_U128_STRING_LEN + 1)
#define MAX_F64_STRING_LEN 64

typedef enum {
	Int128DisplayTypeDecimal,
	Int128DisplayTypeHexUpper,
	Int128DisplayTypeHexLower,
	Int128DisplayTypeBinary,
	Int128DisplayTypeCommas,
} Int128DisplayType;

u64 strlen(const char *msg);
i32 strncmp(const char *x, const char *y, u64 n);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dst, const char *src, u64 n);
i32 strcmp(const char *x, const char *y);
char *strstr(const char *s, const char *sub);
char *strcat(char *dest, const char *src);
char *strchr(const char *s, i32 c);
void *memset(void *ptr, i32 x, u64 n);
void *memcpy(void *dst, const void *src, u64 n);
void *memmove(void *dst, const void *src, u64 n);
i32 memcmp(const void *s1, const void *s2, u64 n);
u8 f64_to_string(u8 buf[MAX_F64_STRING_LEN], f64 v, i32 max_decimals,
		 bool commas);
i32 string_to_u128(const u8 *buf, u64 len, u128 *result);
u8 i128_to_string(u8 buf[MAX_I128_STRING_LEN], i128 value, Int128DisplayType t);
u8 u128_to_string(u8 buf[MAX_U128_STRING_LEN], u128 value, Int128DisplayType t);

__attribute__((unused, noinline)) static void secure_zero(void *ptr, u64 len) {
	volatile u8 *p = (volatile u8 *)ptr;
	while (len--) *p++ = 0;
}

void secure_zero32(u8 buf[32]);

#endif /* _STRING_H */
