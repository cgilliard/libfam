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

#include <libfam/env.h>
#include <libfam/main.h>
#include <libfam/sysext.h>
#include <libfam/test_base.h>

const u8 *SPACER =(void*)
    "------------------------------------------------------------------"
    "--------------------------\n";

i32 cur_tests = 0;
i32 exe_test = 0;
i32 cur_benches = 0;

TestEntry tests[MAX_TESTS];
TestEntry benches[MAX_TESTS];
TestEntry *active;

PUBLIC void add_test_fn(void (*test_fn)(void), const u8 *name) {
	if (__builtin_strlen((void *)name) > MAX_TEST_NAME) {
		const u8 *msg = (void *)"test name too long!\n";
		pwrite(2, msg, __builtin_strlen((void *)msg), 0);
		exit_group(-1);
	}
	if (cur_tests >= MAX_TESTS) {
		const u8 *msg = (void *)"too many tests!";
		pwrite(2, msg, __builtin_strlen((void *)msg), 0);
		exit_group(-1);
	}
	tests[cur_tests].test_fn = test_fn;
	__builtin_memset(tests[cur_tests].name, 0, MAX_TEST_NAME);
	__builtin_strcpy((void *)tests[cur_tests].name, (void *)name);
	cur_tests++;
}

void add_bench_fn(void (*test_fn)(void), const u8 *name) {
	if (__builtin_strlen((void *)name) > MAX_TEST_NAME) {
		const u8 *msg = (void *)"bench name too long!\n";
		pwrite(2, msg, __builtin_strlen((void *)msg), 0);
		exit_group(-1);
	}
	if (cur_tests >= MAX_TESTS) {
		const u8 *msg = (void *)"too many benches!";
		pwrite(2, msg, __builtin_strlen((void *)msg), 0);
		exit_group(-1);
	}
	benches[cur_benches].test_fn = test_fn;
	__builtin_memset(benches[cur_benches].name, 0, MAX_TEST_NAME);
	__builtin_strcpy((void *)benches[cur_benches].name, (void *)name);
	cur_benches++;
}

i32 run_tests(u8 **envp) {
	u8 *pattern;
	u64 total, len, test_count = 0;
	f64 ms;
	u8 buf[64];

	if (init_environ(envp) < 0) {
		perror("init_environ");
		const u8 *msg = (void *)"Too many environment variables!\n";
		pwrite(2, msg, __builtin_strlen((void *)msg), 0);
		exit_group(-1);
	}

	pattern = (void *)getenv("TEST_PATTERN");

	pwrite(2, (void *)CYAN, __builtin_strlen((void *)CYAN), 0);
	if (!pattern || !__builtin_strcmp((void *)pattern, (void *)"*")) {
		pwrite(2, (void *)"Running ",
		       __builtin_strlen((void *)"Running "), 0);
		write_num(2, cur_tests);
		pwrite(2, (void *)" tests", __builtin_strlen((void *)" tests"),
		       0);
		pwrite(2, (void *)RESET, __builtin_strlen((void *)RESET), 0);
		pwrite(2, (void *)"...\n", 4, 0);
	} else {
		pwrite(2, (void *)"Running test",
		       __builtin_strlen((void *)"Running test"), 0);
		pwrite(2, (void *)RESET, __builtin_strlen((void *)RESET), 0);
		pwrite(2, (void *)": '", 3, 0);
		pwrite(2, (void *)pattern, __builtin_strlen((void *)pattern),
		       0);
		pwrite(2, "' ...\n", 6, 0);
	}

	pwrite(2, (void *)SPACER, __builtin_strlen((void *)SPACER), 0);

	total = micros();
	heap_bytes_reset();
	open_fds_reset();

	for (exe_test = 0; exe_test < cur_tests; exe_test++) {
		if (!pattern ||
		    !__builtin_strcmp((void *)pattern, (void *)"*") ||
		    !__builtin_strcmp((void *)pattern,
				      (void *)tests[exe_test].name)) {
			i64 start = micros();
			pwrite(2, (void *)YELLOW,
			       __builtin_strlen((void *)YELLOW), 0);
			pwrite(2, (void *)"Running test",
			       __builtin_strlen((void *)"Running test"), 0);
			pwrite(2, (void *)RESET,
			       __builtin_strlen((void *)RESET), 0);
			pwrite(2, (void *)" ", 1, 0);
			write_num(2, ++test_count);
			pwrite(2, " [", 2, 0);
			pwrite(2, (void *)DIMMED,
			       __builtin_strlen((void *)DIMMED), 0);
			pwrite(2, tests[exe_test].name,
			       __builtin_strlen((void *)tests[exe_test].name),
			       0);
			pwrite(2, (void *)RESET,
			       __builtin_strlen((void *)RESET), 0);

			pwrite(2, (void *)"] ", 2, 0);

			tests[exe_test].test_fn();

			pwrite(2, (void *)GREEN,
			       __builtin_strlen((void *)GREEN), 0);
			pwrite(2, "[", 1, 0);
			write_num(2, (i64)(micros() - start));
			pwrite(2, (void *)"µs", __builtin_strlen((void *)"µs"),
			       0);
			pwrite(2, "]\n", 2, 0);
			pwrite(2, (void *)RESET,
			       __builtin_strlen((void *)RESET), 0);
		}
		ASSERT_BYTES(0);
		ASSERT_OPEN_FDS(0);
	}

	ms = (f64)(micros() - total) / (f64)1000;
	len = f64_to_string(buf, ms, 3, false);
	buf[len] = 0;

	pwrite(2, (void *)SPACER, __builtin_strlen((void *)SPACER), 0);

	pwrite(2, (void *)GREEN, __builtin_strlen((void *)GREEN), 0);
	pwrite(2, (void *)"Success", __builtin_strlen((void *)"Success"), 0);
	pwrite(2, (void *)RESET, __builtin_strlen((void *)RESET), 0);
	pwrite(2, (void *)"! ", 2, 0);
	write_num(2, test_count);
	pwrite(2, (void *)" ", 1, 0);
	pwrite(2, (void *)CYAN, __builtin_strlen((void *)CYAN), 0);
	pwrite(2, (void *)"tests passed!",
	       __builtin_strlen((void *)"tests passed!"), 0);
	pwrite(2, (void *)RESET, __builtin_strlen((void *)RESET), 0);
	pwrite(2, (void *)GREEN, __builtin_strlen((void *)GREEN), 0);
	pwrite(2, " [", 2, 0);
	pwrite(2, (void *)buf, __builtin_strlen((void *)buf), 0);
	pwrite(2, " ms]\n", 5, 0);
	pwrite(2, (void *)RESET, __builtin_strlen((void *)RESET), 0);

	return 0;
}

i32 run_benches(u8 **envp) {
	u8 *pattern;
	u64 total, len, bench_count = 0;
	f64 ms;
	u8 buf[64];

	if (init_environ(envp) < 0) {
		perror("init_environ");
		const u8 *msg = (void *)"Too many environment variables!\n";
		pwrite(2, msg, __builtin_strlen((void *)msg), 0);
		exit_group(-1);
	}

	pattern = (void *)getenv("TEST_PATTERN");

	pwrite(2, (void *)CYAN, __builtin_strlen((void *)CYAN), 0);
	if (!pattern || !__builtin_strcmp((void *)pattern, (void *)"*")) {
		pwrite(2, (void *)"Running ",
		       __builtin_strlen((void *)"Running "), 0);
		write_num(2, cur_benches);
		pwrite(2, (void *)" benches",
		       __builtin_strlen((void *)" benches"), 0);
		pwrite(2, (void *)RESET, __builtin_strlen((void *)RESET), 0);
		pwrite(2, (void *)"...\n", 4, 0);
	} else {
		pwrite(2, (void *)"Running bench",
		       __builtin_strlen((void *)"Running bench"), 0);
		pwrite(2, (void *)RESET, __builtin_strlen((void *)RESET), 0);
		pwrite(2, (void *)": '", 3, 0);
		pwrite(2, (void *)pattern, __builtin_strlen((void *)pattern),
		       0);
		pwrite(2, "' ...\n", 6, 0);
	}

	pwrite(2, (void *)SPACER, __builtin_strlen((void *)SPACER), 0);

	heap_bytes_reset();
	open_fds_reset();
	total = micros();

	for (exe_test = 0; exe_test < cur_benches; exe_test++) {
		if (!pattern ||
		    !__builtin_strcmp((void *)pattern, (void *)"*") ||
		    !__builtin_strcmp((void *)pattern,
				      (void *)benches[exe_test].name)) {
			pwrite(2, (void *)YELLOW,
			       __builtin_strlen((void *)YELLOW), 0);
			pwrite(2, (void *)"Running bench",
			       __builtin_strlen((void *)"Running bench"), 0);
			pwrite(2, (void *)RESET,
			       __builtin_strlen((void *)RESET), 0);
			pwrite(2, (void *)" ", 1, 0);
			write_num(2, ++bench_count);
			pwrite(2, " [", 2, 0);
			pwrite(2, (void *)DIMMED,
			       __builtin_strlen((void *)DIMMED), 0);
			pwrite(2, benches[exe_test].name,
			       __builtin_strlen((void *)benches[exe_test].name),
			       0);
			pwrite(2, (void *)RESET,
			       __builtin_strlen((void *)RESET), 0);

			pwrite(2, (void *)"] ", 2, 0);

			benches[exe_test].test_fn();
		}
		ASSERT_BYTES(0);
		ASSERT_OPEN_FDS(0);
	}

	ms = (f64)(micros() - total) / (f64)1000;
	len = f64_to_string(buf, ms, 3, false);
	buf[len] = 0;

	pwrite(2, (void *)SPACER, __builtin_strlen((void *)SPACER), 0);

	pwrite(2, (void *)GREEN, __builtin_strlen((void *)GREEN), 0);
	pwrite(2, (void *)"Success", __builtin_strlen((void *)"Success"), 0);
	pwrite(2, (void *)RESET, __builtin_strlen((void *)RESET), 0);
	pwrite(2, (void *)"! ", 2, 0);
	write_num(2, bench_count);
	pwrite(2, (void *)" ", 1, 0);
	pwrite(2, (void *)CYAN, __builtin_strlen((void *)CYAN), 0);
	pwrite(2, (void *)"benches passed!",
	       __builtin_strlen((void *)"benches passed!"), 0);
	pwrite(2, (void *)RESET, __builtin_strlen((void *)RESET), 0);
	pwrite(2, (void *)GREEN, __builtin_strlen((void *)GREEN), 0);
	pwrite(2, " [", 2, 0);
	pwrite(2, (void *)buf, __builtin_strlen((void *)buf), 0);
	pwrite(2, " ms]\n", 5, 0);
	pwrite(2, (void *)RESET, __builtin_strlen((void *)RESET), 0);

	return 0;
}

i32 main(i32 argc, u8 **argv, u8 **envp) {
	if (argc >= 2 && !__builtin_strcmp(argv[1], "bench")) {
		active = benches;
		return run_benches(envp);
	} else {
		active = tests;
		return run_tests(envp);
	}
}

