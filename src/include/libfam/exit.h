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

#ifndef _EXIT_H
#define _EXIT_H

#include <libfam/sysext.h>
#include <libfam/types.h>

#define MAX_EXITS 100

typedef struct {
	void (*exit_fn)(void);
} ExitEntry;

extern i32 cur_exits;
extern ExitEntry exits[MAX_EXITS];

static inline void add_exit_fn(void (*exit_fn)(void)) {
	if (cur_exits >= MAX_EXITS) {
		const u8 *msg = (void *)"too many exits!";
		pwrite(2, msg, __builtin_strlen((void *)msg), 0);
		return;
	}
	exits[cur_exits++].exit_fn = exit_fn;
}

#define ON_EXIT(name)                                                  \
	void __##name##__on_exit(void);                                \
	__attribute__((constructor)) void __##name##__register(void) { \
		add_exit_fn(__##name##__on_exit);                      \
	}                                                              \
	void __##name##__on_exit(void)

#endif /* _EXIT_H */

