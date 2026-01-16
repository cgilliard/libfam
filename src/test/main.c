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

#include <libfam/debug.h>
#include <libfam/env.h>
#include <libfam/errno.h>
#include <libfam/linux.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/test_base.h>
#include <libfam/types.h>
#include <libfam/utils.h>

#define TEST_COMPLETE "/tmp/test_complete"

const u8 *SUCCESS_PATH = (void *)"/tmp/libfam_test_success";
const u8 *SPACER =(void*)
    "------------------------------------------------------------------"
    "--------------------------\n";

i32 cur_tests = 0;
i32 exe_test = 0;
i32 cur_benches = 0;

TestEntry tests[MAX_TESTS];
TestEntry benches[MAX_TESTS];
TestEntry *active;

void add_test_fn(void (*test_fn)(void), const u8 *name) {
	if (faststrlen((void *)name) > MAX_TEST_NAME) {
		const u8 *msg = (void *)"test name too long!\n";
		pwrite(2, msg, faststrlen((void *)msg), 0);
		_exit(-1);
	}
	if (cur_tests >= MAX_TESTS) {
		const u8 *msg = (void *)"too many tests!";
		pwrite(2, msg, faststrlen((void *)msg), 0);
		_exit(-1);
	}
	tests[cur_tests].test_fn = test_fn;
	fastmemset(tests[cur_tests].name, 0, MAX_TEST_NAME);
	strcpy((void *)tests[cur_tests].name, (void *)name);
	cur_tests++;
}

void add_bench_fn(void (*test_fn)(void), const u8 *name) {
	if (faststrlen((void *)name) > MAX_TEST_NAME) {
		const u8 *msg = (void *)"bench name too long!\n";
		pwrite(2, msg, faststrlen((void *)msg), 0);
		_exit(-1);
	}
	if (cur_tests >= MAX_TESTS) {
		const u8 *msg = (void *)"too many benches!";
		pwrite(2, msg, faststrlen((void *)msg), 0);
		_exit(-1);
	}
	benches[cur_benches].test_fn = test_fn;
	fastmemset(benches[cur_benches].name, 0, MAX_TEST_NAME);
	strcpy((void *)benches[cur_benches].name, (void *)name);
	cur_benches++;
}

#ifndef COVERAGE
#ifdef __aarch64__
__asm__(
    ".section .text\n"
    ".global _start\n"
    "_start:\n"
    "    ldr x0, [sp]\n"
    "    add x1, sp, #8\n"
    "    add x3, x0, #1\n"
    "    lsl x3, x3, #3\n"
    "    add x2, x1, x3\n"
    "    mov x4, sp\n"
    "    bic x4, x4, #15\n"
    "    mov sp, x4\n"
    "    bl main\n"
    "    mov x0, x0\n"
    "    mov x8, #93\n"
    "    svc #0\n");
#elif defined(__x86_64__)
__asm__(
    ".section .text\n"
    ".global _start\n"
    "_start:\n"
    "    movq (%rsp), %rdi\n"
    "    lea 8(%rsp), %rsi\n"
    "    mov %rdi, %rcx\n"
    "    add $1, %rcx\n"
    "    shl $3, %rcx\n"
    "    lea (%rsi, %rcx), %rdx\n"
    "    mov %rsp, %rcx\n"
    "    and $-16, %rsp\n"
    "    call main\n"
    "    mov %rax, %rdi\n"
    "    mov $60, %rax\n"
    "    syscall\n");
#endif /* __x86_64__ */
#endif /* COVERAGE */

i32 run_tests(u8 **envp) {
	u8 *pattern;
	u64 total, len, test_count = 0;
	f64 ms;
	u8 buf[64];

	if (init_environ(envp) < 0) {
		perror("init_environ");
		const u8 *msg = (void *)"Too many environment variables!\n";
		pwrite(2, msg, faststrlen((void *)msg), 0);
		_exit(-1);
	}

	pattern = (void *)getenv("TEST_PATTERN");

	pwrite(2, (void *)CYAN, faststrlen((void *)CYAN), 0);
	if (!pattern || !strcmp((void *)pattern, (void *)"*")) {
		pwrite(2, (void *)"Running ", faststrlen((void *)"Running "),
		       0);
		write_num(2, cur_tests);
		pwrite(2, (void *)" tests", faststrlen((void *)" tests"), 0);
		pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);
		pwrite(2, (void *)"...\n", 4, 0);
	} else {
		pwrite(2, (void *)"Running test",
		       faststrlen((void *)"Running test"), 0);
		pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);
		pwrite(2, (void *)": '", 3, 0);
		pwrite(2, (void *)pattern, faststrlen((void *)pattern), 0);
		pwrite(2, "' ...\n", 6, 0);
	}

	pwrite(2, (void *)SPACER, faststrlen((void *)SPACER), 0);

	total = micros();
	heap_bytes_reset();

	for (exe_test = 0; exe_test < cur_tests; exe_test++) {
		if (!pattern || !strcmp((void *)pattern, (void *)"*") ||
		    !strcmp((void *)pattern, (void *)tests[exe_test].name)) {
			i64 start = micros();
			pwrite(2, (void *)YELLOW, faststrlen((void *)YELLOW),
			       0);
			pwrite(2, (void *)"Running test",
			       faststrlen((void *)"Running test"), 0);
			pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);
			pwrite(2, (void *)" ", 1, 0);
			write_num(2, ++test_count);
			pwrite(2, " [", 2, 0);
			pwrite(2, (void *)DIMMED, faststrlen((void *)DIMMED),
			       0);
			pwrite(2, tests[exe_test].name,
			       faststrlen((void *)tests[exe_test].name), 0);
			pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);

			pwrite(2, (void *)"] ", 2, 0);

			tests[exe_test].test_fn();

			pwrite(2, (void *)GREEN, faststrlen((void *)GREEN), 0);
			pwrite(2, "[", 1, 0);
			write_num(2, (i64)(micros() - start));
			pwrite(2, (void *)"µs", faststrlen((void *)"µs"), 0);
			pwrite(2, "]\n", 2, 0);
			pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);
		}
		ASSERT_BYTES(0);
		ASSERT_OPEN_FDS(0);
	}

	ms = (f64)(micros() - total) / (f64)1000;
	len = f64_to_string(buf, ms, 3, false);
	buf[len] = 0;

	pwrite(2, (void *)SPACER, faststrlen((void *)SPACER), 0);

	pwrite(2, (void *)GREEN, faststrlen((void *)GREEN), 0);
	pwrite(2, (void *)"Success", faststrlen((void *)"Success"), 0);
	pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);
	pwrite(2, (void *)"! ", 2, 0);
	write_num(2, test_count);
	pwrite(2, (void *)" ", 1, 0);
	pwrite(2, (void *)CYAN, faststrlen((void *)CYAN), 0);
	pwrite(2, (void *)"tests passed!", faststrlen((void *)"tests passed!"),
	       0);
	pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);
	pwrite(2, (void *)GREEN, faststrlen((void *)GREEN), 0);
	pwrite(2, " [", 2, 0);
	pwrite(2, (void *)buf, faststrlen((void *)buf), 0);
	pwrite(2, " ms]\n", 5, 0);
	pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);

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
		pwrite(2, msg, faststrlen((void *)msg), 0);
		_exit(-1);
	}

	pattern = (void *)getenv("TEST_PATTERN");

	pwrite(2, (void *)CYAN, faststrlen((void *)CYAN), 0);
	if (!pattern || !strcmp((void *)pattern, (void *)"*")) {
		pwrite(2, (void *)"Running ", faststrlen((void *)"Running "),
		       0);
		write_num(2, cur_benches);
		pwrite(2, (void *)" benches", faststrlen((void *)" benches"),
		       0);
		pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);
		pwrite(2, (void *)"...\n", 4, 0);
	} else {
		pwrite(2, (void *)"Running bench",
		       faststrlen((void *)"Running bench"), 0);
		pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);
		pwrite(2, (void *)": '", 3, 0);
		pwrite(2, (void *)pattern, faststrlen((void *)pattern), 0);
		pwrite(2, "' ...\n", 6, 0);
	}

	pwrite(2, (void *)SPACER, faststrlen((void *)SPACER), 0);

	heap_bytes_reset();
	total = micros();

	for (exe_test = 0; exe_test < cur_benches; exe_test++) {
		if (!pattern || !strcmp((void *)pattern, (void *)"*") ||
		    !strcmp((void *)pattern, (void *)benches[exe_test].name)) {
			pwrite(2, (void *)YELLOW, faststrlen((void *)YELLOW),
			       0);
			pwrite(2, (void *)"Running bench",
			       faststrlen((void *)"Running bench"), 0);
			pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);
			pwrite(2, (void *)" ", 1, 0);
			write_num(2, ++bench_count);
			pwrite(2, " [", 2, 0);
			pwrite(2, (void *)DIMMED, faststrlen((void *)DIMMED),
			       0);
			pwrite(2, benches[exe_test].name,
			       faststrlen((void *)benches[exe_test].name), 0);
			pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);

			pwrite(2, (void *)"] ", 2, 0);

			benches[exe_test].test_fn();
		}
		ASSERT_BYTES(0);
		ASSERT_OPEN_FDS(0);
	}

	ms = (f64)(micros() - total) / (f64)1000;
	len = f64_to_string(buf, ms, 3, false);
	buf[len] = 0;

	pwrite(2, (void *)SPACER, faststrlen((void *)SPACER), 0);

	pwrite(2, (void *)GREEN, faststrlen((void *)GREEN), 0);
	pwrite(2, (void *)"Success", faststrlen((void *)"Success"), 0);
	pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);
	pwrite(2, (void *)"! ", 2, 0);
	write_num(2, bench_count);
	pwrite(2, (void *)" ", 1, 0);
	pwrite(2, (void *)CYAN, faststrlen((void *)CYAN), 0);
	pwrite(2, (void *)"benches passed!",
	       faststrlen((void *)"benches passed!"), 0);
	pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);
	pwrite(2, (void *)GREEN, faststrlen((void *)GREEN), 0);
	pwrite(2, " [", 2, 0);
	pwrite(2, (void *)buf, faststrlen((void *)buf), 0);
	pwrite(2, " ms]\n", 5, 0);
	pwrite(2, (void *)RESET, faststrlen((void *)RESET), 0);

	return 0;
}

i32 main(i32 argc, u8 **argv, u8 **envp) {
	if (argc >= 2 && !strcmp(argv[1], "bench")) {
		active = benches;
		return run_benches(envp);
	} else {
		active = tests;
		return run_tests(envp);
	}
}

