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

#ifndef _UTILS_H
#define _UTILS_H

#include <libfam/errno.h>

#define PUBLIC __attribute__((visibility("default")))

#define STATIC_ASSERT(condition, message) \
	typedef u8 static_assert_##message[(condition) ? 1 : -1]

#define min(a, b) ((a) - (((a) - (b)) & -((a) > (b))))
#define max(a, b) ((a) - (((a) - (b)) & -((a) < (b))))

#define EXPAND(x) x
#define EXPAND_ALL(...) __VA_ARGS__
#define EMPTY()
#define DEFER1(m) m EMPTY()

#define EVAL(...) EVAL64(__VA_ARGS__)
#define EVAL64(...) EVAL32(EVAL32(__VA_ARGS__))
#define EVAL32(...) EVAL16(EVAL16(__VA_ARGS__))
#define EVAL16(...) EVAL8(EVAL8(__VA_ARGS__))
#define EVAL8(...) EVAL4(EVAL4(__VA_ARGS__))
#define EVAL4(...) EVAL2(EVAL2(__VA_ARGS__))
#define EVAL2(...) EVAL1(EVAL1(__VA_ARGS__))
#define EVAL1(...) __VA_ARGS__

#define MAP(m, arg, delim, first, ...) \
	m(arg, first) __VA_OPT__(      \
	    EXPAND_ALL delim DEFER1(_MAP)()(m, arg, delim, __VA_ARGS__))
#define _MAP() MAP

#define FOR_EACH(m, arg, delim, ...) \
	EVAL(__VA_OPT__(MAP(m, arg, delim, __VA_ARGS__)))

#ifndef offsetof
#define offsetof(type, member) ((u64) & (((type *)0)->member))
#endif

#define ERR(v)             \
	do {               \
		errno = v; \
		return -1; \
	} while (0);

#endif /* _UTILS_H */
