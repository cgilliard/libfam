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
#include <libfam/format.h>
#include <libfam/main.h>
#include <libfam/sysext.h>
#include <libfam/test.h>

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
	if (__builtin_strlen((void *)name) > MAX_TEST_NAME)
		panic("Test name too long!");
	if (cur_tests >= MAX_TESTS) panic("Too many tests!");

	tests[cur_tests].test_fn = test_fn;
	__builtin_memset(tests[cur_tests].name, 0, MAX_TEST_NAME);
	__builtin_strcpy((void *)tests[cur_tests].name, (void *)name);
	cur_tests++;
}

void add_bench_fn(void (*test_fn)(void), const u8 *name) {
	if (__builtin_strlen((void *)name) > MAX_TEST_NAME)
		panic("bench name too long!");
	if (cur_benches >= MAX_TESTS) panic("Too many benches!");

	benches[cur_benches].test_fn = test_fn;
	__builtin_memset(benches[cur_benches].name, 0, MAX_TEST_NAME);
	__builtin_strcpy((void *)benches[cur_benches].name, (void *)name);
	cur_benches++;
}

i32 run_tests(u8 **envp) {
	u8 *pattern;
	u64 total, test_count = 0;
	f64 ms;

	if (init_environ(envp) < 0) {
		perror("init_environ");
		panic("Too many environment variables!");
	}

	pattern = (void *)getenv("TEST_PATTERN");

	if (!pattern || !__builtin_strcmp((void *)pattern, (void *)"*"))
		println("{}Running {} tests{}...", CYAN, cur_tests, RESET);
	else
		println("{}Running test{}: {}...", CYAN, RESET, pattern);

	print("{}", SPACER);

	total = micros();
	heap_bytes_reset();
	open_fds_reset();

	for (exe_test = 0; exe_test < cur_tests; exe_test++) {
		if (!pattern ||
		    !__builtin_strcmp((void *)pattern, (void *)"*") ||
		    !__builtin_strcmp((void *)pattern,
				      (void *)tests[exe_test].name)) {
			print("{}Running test{} {} [{}{}{}] ", YELLOW, RESET,
			      ++test_count, DIMMED, tests[exe_test].name,
			      RESET);
			i64 timer = micros();
			tests[exe_test].test_fn();
			timer = micros() - timer;

			println("{}[{}µs]{}", GREEN, timer, RESET);
		}
		ASSERT_BYTES(0);
		ASSERT_OPEN_FDS(0);
	}

	ms = (f64)(micros() - total) / (f64)1000;

	println("{}{}Success{}! {} {}tests passed!{} {}[{} ms]{}", SPACER,
		GREEN, RESET, test_count, CYAN, RESET, GREEN, ms, RESET);
	return 0;
}

i32 run_benches(u8 **envp) {
	u8 *pattern;
	u64 total, bench_count = 0;
	f64 ms;

	if (init_environ(envp) < 0) {
		perror("init_environ");
		panic("Too many environment variables!");
	}

	pattern = (void *)getenv("TEST_PATTERN");

	if (!pattern || !__builtin_strcmp((void *)pattern, (void *)"*")) {
		println("{}Running {} benchs{}...", CYAN, cur_benches, RESET);
	} else {
		println("{}Running bench{}: '{}' ...", CYAN, RESET, pattern);
	}
	print("{}", SPACER);

	heap_bytes_reset();
	open_fds_reset();
	total = micros();

	for (exe_test = 0; exe_test < cur_benches; exe_test++) {
		if (!pattern ||
		    !__builtin_strcmp((void *)pattern, (void *)"*") ||
		    !__builtin_strcmp((void *)pattern,
				      (void *)benches[exe_test].name)) {
			println("{}Running bench{} {} [{}{}{}]", YELLOW, RESET,
				++bench_count, DIMMED, benches[exe_test].name,
				RESET);
			benches[exe_test].test_fn();
		}
		ASSERT_BYTES(0);
		ASSERT_OPEN_FDS(0);
	}

	ms = (f64)(micros() - total) / (f64)1000;
	println("{}{}Success{}! {} {}benches passed!{} {}[{} ms]{}", SPACER,
		GREEN, RESET, bench_count, CYAN, RESET, GREEN, ms, RESET);

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

