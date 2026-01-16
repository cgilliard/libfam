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

#ifndef _TEST_H
#define _TEST_H

#include <libfam/format.h>
#include <libfam/test_base.h>

#undef ASSERT_EQ
#define ASSERT_EQ(x, y, ...)                                                   \
	({                                                                     \
		if ((x) != (y)) {                                              \
			Formatter fmt = FORMATTER_INIT;                        \
			__VA_OPT__(FORMAT(&fmt, __VA_ARGS__);)                 \
			println("{}{}{}: [{}]. '{}'", BRIGHT_RED,              \
				__assertion_msg, RESET, active[exe_test].name, \
				format_to_string(&fmt));                       \
			exit_group(-1);                                             \
		}                                                              \
	})

#undef ASSERT
#define ASSERT(x, ...)                                                         \
	({                                                                     \
		if (!(x)) {                                                    \
			Formatter fmt = FORMATTER_INIT;                        \
			__VA_OPT__(FORMAT(&fmt, __VA_ARGS__);)                 \
			println("{}{}{}: [{}]. '{}'", BRIGHT_RED,              \
				__assertion_msg, RESET, active[exe_test].name, \
				format_to_string(&fmt));                       \
			exit_group(-1);                                             \
		}                                                              \
	})

#endif /* _TEST_H */
