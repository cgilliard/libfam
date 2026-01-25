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

#ifndef _FORMAT_H
#define _FORMAT_H

#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/types.h>
#include <libfam/utils.h>

#define FORMATTER_INIT {0};

#define FORMAT_ITEM(ign, value)                                                \
	({                                                                     \
		Printable _p__ = _Generic((value),                             \
		    char: ((Printable){                                        \
			.t = IntType,                                          \
			.data.ivalue =                                         \
			    _Generic((value), char: (value), default: 0)}),    \
		    signed char: ((Printable){.t = IntType,                    \
					      .data.ivalue = _Generic((value), \
					      signed char: (value),            \
					      default: 0)}),                   \
		    short int: ((Printable){.t = IntType,                      \
					    .data.ivalue = _Generic((value),   \
					    short int: (value),                \
					    default: 0)}),                     \
		    int: ((Printable){                                         \
			.t = IntType,                                          \
			.data.ivalue =                                         \
			    _Generic((value), int: (value), default: 0)}),     \
		    long: ((Printable){                                        \
			.t = IntType,                                          \
			.data.ivalue =                                         \
			    _Generic((value), long: (value), default: 0)}),    \
		    long long: ((Printable){.t = IntType,                      \
					    .data.ivalue = _Generic((value),   \
					    long long: (value),                \
					    default: 0)}),                     \
		    __int128_t: ((Printable){.t = IntType,                     \
					     .data.ivalue = _Generic((value),  \
					     __int128_t: (value),              \
					     default: 0)}),                    \
		    unsigned char: ((Printable){                               \
			.t = UIntType,                                         \
			.data.uvalue = _Generic((value),                       \
			unsigned char: (value),                                \
			default: 0)}),                                         \
		    unsigned short int: ((Printable){                          \
			.t = UIntType,                                         \
			.data.uvalue = _Generic((value),                       \
			unsigned short int: (value),                           \
			default: 0)}),                                         \
		    unsigned int: ((Printable){                                \
			.t = UIntType,                                         \
			.data.uvalue = _Generic((value),                       \
			unsigned int: (value),                                 \
			default: 0)}),                                         \
		    unsigned long: ((Printable){                               \
			.t = UIntType,                                         \
			.data.uvalue = _Generic((value),                       \
			unsigned long: (value),                                \
			default: 0)}),                                         \
		    unsigned long long: ((Printable){                          \
			.t = UIntType,                                         \
			.data.uvalue = _Generic((value),                       \
			unsigned long long: (value),                           \
			default: 0)}),                                         \
		    __uint128_t: ((Printable){.t = UIntType,                   \
					      .data.uvalue = _Generic((value), \
					      __uint128_t: (value),            \
					      default: 0)}),                   \
		    char *: ((Printable){.t = StringType,                      \
					 .data.svalue = _Generic((value),      \
					 char *: (value),                      \
					 default: NULL)}),                     \
		    const char *: ((Printable){                                \
			.t = StringType,                                       \
			.data.svalue = _Generic((value),                       \
			const char *: (value),                                 \
			default: NULL)}),                                      \
		    signed char *: ((Printable){                               \
			.t = StringType,                                       \
			.data.svalue = _Generic((value),                       \
			char *: (value),                                       \
			default: NULL)}),                                      \
		    u8 *: ((Printable){.t = StringType,                        \
				       .data.svalue = _Generic((value),        \
				       const u8 *: (value),                    \
				       u8 *: (value),                          \
				       default: NULL)}),                       \
		    const u8 *: ((Printable){.t = StringType,                  \
					     .data.svalue = _Generic((value),  \
					     const u8 *: (value),              \
					     default: NULL)}),                 \
		    void *: ((Printable){.t = UIntType,                        \
					 .data.uvalue = _Generic((value),      \
					 void *: ((u64)value),                 \
					 default: 0)}),                        \
		    double: ((Printable){.t = FloatType,                       \
					 .data.fvalue = _Generic((value),      \
					 double: (value),                      \
					 default: 0.0)}),                      \
		    float: ((Printable){                                       \
			.t = FloatType,                                        \
			.data.fvalue =                                         \
			    _Generic((value), float: (value), default: 0.0)}), \
		    default: ((Printable){                                     \
			.t = StringType,                                       \
			.data.svalue = (u8 *)"unsupported"}));                 \
		_p__;                                                          \
	})

#ifdef __clang__
#define FORMAT(f, fmt, ...)                                                    \
	({                                                                     \
		_Pragma("GCC diagnostic push");                                \
		/* clang-format off */                                       \
		_Pragma("GCC diagnostic ignored \"-Wincompatible-pointer-types-discards-qualifiers\""); \
		/* clang-format on */                                          \
		format_append(                                                 \
		    f, fmt __VA_OPT__(                                         \
			   , FOR_EACH(FORMAT_ITEM, _, (, ), __VA_ARGS__)));    \
		_Pragma("GCC diagnostic pop");                                 \
	})
#else
#define FORMAT(f, fmt, ...)                                                   \
	({                                                                    \
		_Pragma("GCC diagnostic push");                               \
		_Pragma("GCC diagnostic ignored \"-Wdiscarded-qualifiers\""); \
		format_append(                                                \
		    f, fmt __VA_OPT__(                                        \
			   , FOR_EACH(FORMAT_ITEM, _, (, ), __VA_ARGS__)));   \
		_Pragma("GCC diagnostic pop");                                \
	})
#endif

#define println(fmt, ...)                                                     \
	({                                                                    \
		const u8 *_tmp__;                                             \
		Formatter _f__ = {0};                                         \
		if (FORMAT(&_f__, fmt, __VA_ARGS__) >= 0) {                   \
			if (format_append(&_f__, "\n") >= 0) {                \
				_tmp__ = format_to_string(&_f__);             \
				if (_tmp__)                                   \
					pwrite(2, _tmp__, strlen(_tmp__), 0); \
			}                                                     \
		}                                                             \
		format_clear(&_f__);                                          \
	})

#define print(fmt, ...)                                                   \
	({                                                                \
		const u8 *_tmp__;                                         \
		Formatter _f__ = {0};                                     \
		if (FORMAT(&_f__, fmt, __VA_ARGS__) >= 0) {               \
			_tmp__ = format_to_string(&_f__);                 \
			if (_tmp__) pwrite(2, _tmp__, strlen(_tmp__), 0); \
		}                                                         \
		format_clear(&_f__);                                      \
	})

#define panic(fmt, ...)                                                       \
	({                                                                    \
		const u8 *_tmp__;                                             \
		Formatter _f__ = {0};                                         \
		if (FORMAT(&_f__, fmt, __VA_ARGS__) >= 0) {                   \
			if (format_append(&_f__, "\n") >= 0) {                \
				_tmp__ = format_to_string(&_f__);             \
				if (_tmp__)                                   \
					pwrite(2, _tmp__, strlen(_tmp__), 0); \
			}                                                     \
		}                                                             \
		format_clear(&_f__);                                          \
		exit_group(-1);                                               \
	})

typedef struct {
	u8 *buf;
	u64 capacity;
	u64 pos;
} Formatter;

typedef enum {
	IntType,
	UIntType,
	StringType,
	FloatType,
	PRINTABLE_SIZE
} PrintableType;

typedef struct {
	PrintableType t;
	union {
		i128 ivalue;
		u128 uvalue;
		f64 fvalue;
		u8 *svalue;
	} data;
} Printable;

i32 format_append(Formatter *f, const u8 *fmt, ...);
void format_clear(Formatter *f);
const u8 *format_to_string(Formatter *f);

#endif /* _FORMAT_H */
