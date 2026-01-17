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

#include <libfam/async.h>
#include <libfam/atomic.h>
#include <libfam/builtin.h>
#include <libfam/debug.h>
#include <libfam/env.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/rbtree.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/test_base.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif /* PAGE_SIZE */

typedef struct {
	RbTreeNode _reserved;
	u64 value;
} TestRbTreeNode;

i32 test_rbsearch(RbTreeNode *cur, const RbTreeNode *value,
		  RbTreeNodePair *retval) {
	while (cur) {
		u64 v1 = ((TestRbTreeNode *)cur)->value;
		u64 v2 = ((TestRbTreeNode *)value)->value;
		if (v1 == v2) {
			retval->self = cur;
			break;
		} else if (v1 < v2) {
			retval->parent = cur;
			retval->is_right = 1;
			cur = cur->right;
		} else {
			retval->parent = cur;
			retval->is_right = 0;
			cur = cur->left;
		}
		retval->self = cur;
	}
	return 0;
}

#define PARENT(node) ((RbTreeNode *)((u64)node->parent_color & ~0x1))
#define RIGHT(node) node->right
#define LEFT(node) node->left
#define ROOT(tree) (tree->root)
#define IS_RED(node) (node && ((u64)node->parent_color & 0x1))
#define IS_BLACK(node) !IS_RED(node)
#define ROOT(tree) (tree->root)

static bool check_root_black(RbTree *tree) {
	if (!ROOT(tree)) return true;
	return IS_BLACK(ROOT(tree));
}

static bool check_no_consecutive_red(RbTreeNode *node) {
	if (!node) return true;

	if (IS_RED(node)) {
		if (RIGHT(node) && IS_RED(RIGHT(node))) return false;
		if (LEFT(node) && IS_RED(LEFT(node))) return false;
	}

	return check_no_consecutive_red(LEFT(node)) &&
	       check_no_consecutive_red(RIGHT(node));
}

static i32 check_black_height(RbTreeNode *node) {
	i32 left_height, right_height;
	if (!node) return 1;
	left_height = check_black_height(LEFT(node));
	right_height = check_black_height(RIGHT(node));

	if (left_height == -1 || right_height == -1) return -1;

	if (left_height != right_height) return -1;

	return left_height + (IS_BLACK(node) ? 1 : 0);
}

static void validate_rbtree(RbTree *tree) {
	ASSERT(check_root_black(tree), "Root must be black");
	ASSERT(check_no_consecutive_red(ROOT(tree)),
	       "No consecutive red nodes");
	ASSERT(check_black_height(ROOT(tree)) != -1,
	       "Inconsistent black height");
}

Test(rbtree1) {
	RbTree tree = RBTREE_INIT;
	TestRbTreeNode v1 = {{0}, 1};
	TestRbTreeNode v2 = {{0}, 2};
	TestRbTreeNode v3 = {{0}, 3};
	TestRbTreeNode v4 = {{0}, 0};
	TestRbTreeNode vx = {{0}, 3};
	TestRbTreeNode vy = {{0}, 0};
	RbTreeNodePair retval = {0};

	rbtree_put(&tree, (RbTreeNode *)&v1, test_rbsearch);
	validate_rbtree(&tree);
	rbtree_put(&tree, (RbTreeNode *)&v2, test_rbsearch);
	validate_rbtree(&tree);

	test_rbsearch(tree.root, (RbTreeNode *)&v1, &retval);
	ASSERT_EQ(((TestRbTreeNode *)retval.self)->value, 1, "value=1");

	test_rbsearch(tree.root, (RbTreeNode *)&v2, &retval);
	ASSERT_EQ(((TestRbTreeNode *)retval.self)->value, 2, "value=2");
	test_rbsearch(tree.root, (RbTreeNode *)&v3, &retval);
	ASSERT_EQ(retval.self, NULL, "self=NULL");

	rbtree_remove(&tree, (RbTreeNode *)&v2, test_rbsearch);
	validate_rbtree(&tree);
	test_rbsearch(tree.root, (RbTreeNode *)&v2, &retval);
	ASSERT_EQ(retval.self, NULL, "retval=NULL2");
	rbtree_put(&tree, (RbTreeNode *)&v3, test_rbsearch);
	validate_rbtree(&tree);
	rbtree_put(&tree, (RbTreeNode *)&v4, test_rbsearch);
	validate_rbtree(&tree);

	ASSERT_EQ(rbtree_put(&tree, (RbTreeNode *)&vx, test_rbsearch), -1,
		  "duplicate");
	validate_rbtree(&tree);

	ASSERT_EQ(rbtree_put(&tree, (RbTreeNode *)&vy, test_rbsearch), -1,
		  "duplicate2");
	validate_rbtree(&tree);
	ASSERT_BYTES(0);
}

#define SIZE 100

Test(rbtree2) {
	u64 size, i;
	u64 next = 101;

	for (size = 1; size < SIZE; size++) {
		RbTree tree = RBTREE_INIT;
		TestRbTreeNode values[SIZE];
		for (i = 0; i < size; i++) {
			values[i].value = (next++ * 37) % 1001;
			rbtree_put(&tree, (RbTreeNode *)&values[i],
				   test_rbsearch);
			validate_rbtree(&tree);
		}

		for (i = 0; i < size; i++) {
			RbTreeNodePair retval = {0};
			TestRbTreeNode v = {{0}, 0};
			v.value = values[i].value;

			test_rbsearch(tree.root, (RbTreeNode *)&v, &retval);
			ASSERT(retval.self != NULL, "retval=NULL");
			ASSERT_EQ(((TestRbTreeNode *)retval.self)->value,
				  values[i].value, "value=values[i].value");
		}

		for (i = 0; i < size; i++) {
			TestRbTreeNode v = {{0}, 0};
			v.value = values[i].value;
			rbtree_remove(&tree, (RbTreeNode *)&v, test_rbsearch);
			validate_rbtree(&tree);
		}
		ASSERT_EQ(tree.root, NULL, "root=NULL");
		validate_rbtree(&tree);
	}
}

Test(strcmp) {
	ASSERT(strcmp("abc", "def"), "abc!=def");
	ASSERT(!strcmp("abc", "abc"), "abc=abc");
}

Test(strncpy) {
	u8 x[1024] = {0};
	u8 *in1 = "abc\0";
	strncpy(x, in1, 4);
	ASSERT_EQ(x[0], 'a', "a");
	ASSERT_EQ(x[1], 'b', "b");
	ASSERT_EQ(x[2], 'c', "c");
	ASSERT_EQ(x[3], 0, "\0");
}

Test(f64_to_string) {
	u8 buf[64] = {0};
	u64 len;

	len = f64_to_string(buf, 0.3, 1, false);
	ASSERT_EQ(len, 3, "len=3");
	ASSERT(!strcmp(buf, "0.3"), "0.3");

	len = f64_to_string(buf, 0.0 / 0.0, 6, false);
	ASSERT(!strcmp(buf, "nan"), "nan");
	ASSERT_EQ(len, 3, "nan_len");

	len = f64_to_string(buf, 1.0 / 0.0, 6, false);
	ASSERT(!strcmp(buf, "inf"), "inf");
	ASSERT_EQ(len, 3, "inf_len");

	len = f64_to_string(buf, -1.0 / 0.0, 6, false);
	ASSERT(!strcmp(buf, "-inf"), "neg_inf");
	ASSERT_EQ(len, 4, "neg_inf_len");

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Woverflow"
#pragma GCC diagnostic ignored "-Wliteral-range"
	len = f64_to_string(buf, 1.8e308, 6, false);
	ASSERT(!strcmp(buf, "inf"), "overflow_inf");
	ASSERT_EQ(len, 3, "overflow_inf_len");
#pragma GCC diagnostic pop

	len = f64_to_string(buf, 0.0, 6, false);
	ASSERT(!strcmp(buf, "0"), "zero");
	ASSERT_EQ(len, 1, "zero_len");
	len = f64_to_string(buf, -0.0, 6, false);
	ASSERT(!strcmp(buf, "0"), "neg_zero");
	ASSERT_EQ(len, 1, "neg_zero_len");

	len = f64_to_string(buf, 123.0, 0, false);
	ASSERT(!strcmp(buf, "123"), "int_pos");
	ASSERT_EQ(len, 3, "int_pos_len");

	len = f64_to_string(buf, -123.0, 0, false);
	ASSERT(!strcmp(buf, "-123"), "int_neg");

	ASSERT_EQ(len, 4, "int_neg_len");

	len = f64_to_string(buf, 123.456789, 6, false);
	ASSERT(!strcmp(buf, "123.456789"), "frac");
	ASSERT_EQ(len, 10, "frac_len");

	len = f64_to_string(buf, -123.456789, 6, false);
	ASSERT(!strcmp(buf, "-123.456789"), "neg_frac");
	ASSERT_EQ(len, 11, "neg_frac_len");

	len = f64_to_string(buf, 0.9999995, 6, false);
	ASSERT(!strcmp(buf, "1"), "round_up");
	ASSERT_EQ(len, 1, "round_up_len");

	len = f64_to_string(buf, 123.4000, 6, false);
	ASSERT(!strcmp(buf, "123.4"), "trim_zeros");
	ASSERT_EQ(len, 5, "trim_zeros_len");

	len = f64_to_string(buf, 123.0000001, 6, false);
	ASSERT(!strcmp(buf, "123"), "remove_decimal");
	ASSERT_EQ(len, 3, "remove_decimal_len");

	len = f64_to_string(buf, 123.456789123456789, 18, false);
	buf[len] = 0;
	ASSERT(!strcmp(buf, "123.45678912345678668"), "max_decimals");
	ASSERT_EQ(len, 21, "max_decimals_len");

	len = f64_to_string(buf, 123.456, -1, false);
	ASSERT(!strcmp(buf, "123"), "neg_decimals");
	ASSERT_EQ(len, 3, "neg_decimals_len");

	len = f64_to_string(buf, 9993234.334, 2, true);
	ASSERT(!strcmp(buf, "9,993,234.33"), "commas");
	ASSERT_EQ(strlen("9,993,234.33"), len, "commas len");
}

Test(limits) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Woverflow"
#pragma GCC diagnostic ignored "-Winteger-overflow"

	ASSERT(U8_MIN == 0, "U8_MIN should be 0");
	ASSERT(U16_MIN == 0, "U16_MIN should be 0");
	ASSERT(U32_MIN == 0, "U32_MIN should be 0");
	ASSERT(U64_MIN == 0, "U64_MIN should be 0");
	ASSERT(U128_MIN == 0, "U128_MIN should be 0");

	ASSERT(U8_MAX == 0xFF, "U8_MAX should be 255");
	ASSERT(U16_MAX == 0xFFFF, "U16_MAX should be 65535");
	ASSERT(U32_MAX == 0xFFFFFFFF, "U32_MAX should be 4294967295");
	ASSERT(U64_MAX == 0xFFFFFFFFFFFFFFFF,
	       "U64_MAX should be 18446744073709551615");
	u128 u128_max_expected =
	    ((u128)0xFFFFFFFFFFFFFFFFUL << 64) | 0xFFFFFFFFFFFFFFFFUL;
	ASSERT(U128_MAX == u128_max_expected, "U128_MAX incorrect");

	ASSERT(I8_MAX == 0x7F, "I8_MAX should be 127");
	ASSERT(I16_MAX == 0x7FFF, "I16_MAX should be 32767");
	ASSERT(I32_MAX == 0x7FFFFFFF, "I32_MAX should be 2147483647");
	ASSERT(I64_MAX == 0x7FFFFFFFFFFFFFFF,
	       "I64_MAX should be 9223372036854775807");

	i128 i128_max_expected =
	    ((i128)(((i128)0x7FFFFFFFFFFFFFFFUL << 64) | 0xFFFFFFFFFFFFFFFFUL));
	ASSERT(I128_MAX == i128_max_expected, "I128_MAX incorrect");

	ASSERT(I8_MIN == -128, "I8_MIN should be -128");
	ASSERT(I16_MIN == -32768, "I16_MIN should be -32768");
	ASSERT(I32_MIN == -2147483648, "I32_MIN should be -2147483648");
	ASSERT(I64_MIN == I64_MAX + 1,
	       "I64_MIN should be -9223372036854775808");

	i128 i128_min_expected =
	    ((i128)(((u128)0x8000000000000000UL << 64) | 0x0000000000000000UL));
	ASSERT(I128_MIN == i128_min_expected, "I128_MIN");

	ASSERT_EQ((u8)(U8_MAX + 1), U8_MIN, "overflow U8_MAX");
	ASSERT_EQ((u8)(U8_MIN - 1), U8_MAX, "underflow U8_MIN");
	ASSERT_EQ((u16)(U16_MAX + 1), U16_MIN, "overflow U16_MAX");
	ASSERT_EQ((u16)(U16_MIN - 1), U16_MAX, "underflow U16_MIN");
	ASSERT_EQ(U32_MAX + 1, U32_MIN, "overflow U32_MAX");
	ASSERT_EQ(U32_MIN - 1, U32_MAX, "underflow U32_MIN");
	ASSERT_EQ(U64_MAX + 1, U64_MIN, "overflow U64_MAX");
	ASSERT_EQ(U64_MIN - 1, U64_MAX, "underflow U64_MIN");
	ASSERT_EQ(U128_MAX + 1, U128_MIN, "overflow U128_MAX");
	ASSERT_EQ(U128_MIN - 1, U128_MAX, "underflow U128_MIN");
	ASSERT_EQ((i8)(I8_MAX + 1), I8_MIN, "overflow I8_MAX");
	ASSERT_EQ((i8)(I8_MIN - 1), I8_MAX, "underflow I8_MIN");
	ASSERT_EQ((i16)(I16_MAX + 1), I16_MIN, "overflow I16_MAX");
	ASSERT_EQ((i16)(I16_MIN - 1), I16_MAX, "underflow I16_MIN");
	ASSERT_EQ(I32_MAX + 1, I32_MIN, "overflow I32_MAX");
	ASSERT_EQ(I32_MIN - 1, I32_MAX, "underflow I32_MIN");
	ASSERT_EQ(I64_MAX + 1, I64_MIN, "overflow I64_MAX");
	ASSERT_EQ(I64_MIN - 1, I64_MAX, "underflow I64_MIN");
	ASSERT_EQ((i128)(I128_MAX + 1), I128_MIN, "overflow I128_MAX");
	ASSERT_EQ((i128)(I128_MIN - 1), I128_MAX, "underflow I128_MIN");
#pragma GCC diagnostic pop
}

Test(builtins) {
	ASSERT_EQ(clz_u64(0xFFUL), 64 - 8, "0xFFULL");
	ASSERT_EQ(clz_u64(0xFFFFUL), 64 - 16, "0xFFFFULL");
	ASSERT_EQ(clz_u32(0xFFFFFF), 32 - 24, "0xFFFFFF");
	ASSERT_EQ(clz_u32(0xFFFFFFFF), 0, "0xFFFFFFFF");
	ASSERT_EQ(ctz_u32(0xFFFF0), 4, "ctz 0xFFFF0");
	ASSERT_EQ(ctz_u64(0xFFFE0UL), 5, "ctz 0xFFFE0");
	ASSERT_EQ(clz_u128(0xFFFFFFFFFFUL), 128 - 40, "0xFFFFFFFFFFUL");
	ASSERT_EQ(clz_u128((u128)0x1 << 90), 128 - 90 - 1, "t1");
	ASSERT_EQ(clz_u128(0), 128, "clz_128(0)");
}

Test(string_chr_cat) {
	const char *in = "abcdefgh";
	ASSERT_EQ(strchr(in, 'c'), in + 2, "strchr");
	ASSERT_EQ(strchr(in, 'v'), NULL, "strchr miss");
	ASSERT_EQ(strchr(in, 0), in + strlen(in), "strchr strlen");
	u8 buf[1024] = {0};
	strcpy(buf, "abc");
	strcat(buf, "def");
	ASSERT(!strcmp(buf, "abcdef"), "buf");
}

Test(colors) {
	i32 __attribute__((unused)) _v;
	_debug_no_write = true;
	_v = pwrite(2, RED, strlen(RED), 0);
	_v = pwrite(2, BRIGHT_RED, strlen(BRIGHT_RED), 0);
	_v = pwrite(2, MAGENTA, strlen(MAGENTA), 0);
	_v = pwrite(2, BLUE, strlen(BLUE), 0);
	_debug_no_write = false;
}

i32 *__err_location(void);

Test(error) {
	ASSERT(!strcmp(strerror(SUCCESS), "Success"), "SUCCESS → Success");
	ASSERT(!strcmp(strerror(EPERM), "Operation not permitted"),
	       "EPERM → Operation not permitted");
	ASSERT(!strcmp(strerror(ENOENT), "No such file or directory"),
	       "ENOENT → No such file or directory");
	ASSERT(!strcmp(strerror(ESRCH), "No such process"),
	       "ESRCH → No such process");
	ASSERT(!strcmp(strerror(EINTR), "Interrupted system call"),
	       "EINTR → Interrupted system call");
	ASSERT(!strcmp(strerror(EIO), "I/O error"), "EIO → I/O error");
	ASSERT(!strcmp(strerror(ENXIO), "No such device or address"),
	       "ENXIO → No such device or address");
	ASSERT(!strcmp(strerror(E2BIG), "Argument list too long"),
	       "E2BIG → Argument list too long");
	ASSERT(!strcmp(strerror(ENOEXEC), "Exec format error"),
	       "ENOEXEC → Exec format error");
	ASSERT(!strcmp(strerror(EBADF), "Bad file descriptor"),
	       "EBADF → Bad file descriptor");
	ASSERT(!strcmp(strerror(ECHILD), "No child processes"),
	       "ECHILD → No child processes");
	ASSERT(!strcmp(strerror(EAGAIN), "Resource temporarily unavailable"),
	       "EAGAIN → Resource temporarily unavailable");
	ASSERT(!strcmp(strerror(ENOMEM), "Cannot allocate memory"),
	       "ENOMEM → Cannot allocate memory");
	ASSERT(!strcmp(strerror(EACCES), "Permission denied"),
	       "EACCES → Permission denied");
	ASSERT(!strcmp(strerror(EFAULT), "Bad address"),
	       "EFAULT → Bad address");
	ASSERT(!strcmp(strerror(ENOTBLK), "Block device required"),
	       "ENOTBLK → Block device required");
	ASSERT(!strcmp(strerror(EBUSY), "Device or resource busy"),
	       "EBUSY → Device or resource busy");
	ASSERT(!strcmp(strerror(EEXIST), "File exists"),
	       "EEXIST → File exists");
	ASSERT(!strcmp(strerror(EXDEV), "Invalid cross-device link"),
	       "EXDEV → Invalid cross-device link");
	ASSERT(!strcmp(strerror(ENODEV), "No such device"),
	       "ENODEV → No such device");
	ASSERT(!strcmp(strerror(ENOTDIR), "Not a directory"),
	       "ENOTDIR → Not a directory");
	ASSERT(!strcmp(strerror(EISDIR), "Is a directory"),
	       "EISDIR → Is a directory");
	ASSERT(!strcmp(strerror(EINVAL), "Invalid argument"),
	       "EINVAL → Invalid argument");
	ASSERT(!strcmp(strerror(ENFILE), "Too many open files in system"),
	       "ENFILE → Too many open files in system");
	ASSERT(!strcmp(strerror(EMFILE), "Too many open files"),
	       "EMFILE → Too many open files");
	ASSERT(!strcmp(strerror(ENOTTY), "Not a typewriter"),
	       "ENOTTY → Not a typewriter");
	ASSERT(!strcmp(strerror(ETXTBSY), "Text file busy"),
	       "ETXTBSY → Text file busy");
	ASSERT(!strcmp(strerror(EFBIG), "File too large"),
	       "EFBIG → File too large");
	ASSERT(!strcmp(strerror(ENOSPC), "No space left on device"),
	       "ENOSPC → No space left on device");
	ASSERT(!strcmp(strerror(ESPIPE), "Illegal seek"),
	       "ESPIPE → Illegal seek");
	ASSERT(!strcmp(strerror(EROFS), "Read-only file system"),
	       "EROFS → Read-only file system");
	ASSERT(!strcmp(strerror(EMLINK), "Too many links"),
	       "EMLINK → Too many links");
	ASSERT(!strcmp(strerror(EPIPE), "Broken pipe"), "EPIPE → Broken pipe");
	ASSERT(!strcmp(strerror(EDOM), "Math argument out of domain of func"),
	       "EDOM → Math argument out of domain of func");
	ASSERT(!strcmp(strerror(ERANGE), "Math result not representable"),
	       "ERANGE → Math result not representable");
	ASSERT(!strcmp(strerror(EDEADLK), "Resource deadlock would occur"),
	       "EDEADLK → Resource deadlock would occur");
	ASSERT(!strcmp(strerror(ENAMETOOLONG), "File name too long"),
	       "ENAMETOOLONG → File name too long");
	ASSERT(!strcmp(strerror(ENOLCK), "No record locks available"),
	       "ENOLCK → No record locks available");
	ASSERT(!strcmp(strerror(ENOSYS), "Function not implemented"),
	       "ENOSYS → Function not implemented");
	ASSERT(!strcmp(strerror(ENOTEMPTY), "Directory not empty"),
	       "ENOTEMPTY → Directory not empty");
	ASSERT(!strcmp(strerror(ELOOP), "Too many symbolic links encountered"),
	       "ELOOP → Too many symbolic links encountered");

	/* Network & io_uring errors you can actually hit */
	ASSERT(!strcmp(strerror(ENOTSOCK), "Socket operation on non-socket"),
	       "ENOTSOCK → Socket operation on non-socket");
	ASSERT(!strcmp(strerror(EDESTADDRREQ), "Destination address required"),
	       "EDESTADDRREQ → Destination address required");
	ASSERT(!strcmp(strerror(EMSGSIZE), "Message too long"),
	       "EMSGSIZE → Message too long");
	ASSERT(!strcmp(strerror(EPROTOTYPE), "Protocol wrong type for socket"),
	       "EPROTOTYPE → Protocol wrong type for socket");
	ASSERT(!strcmp(strerror(ENOPROTOOPT), "Protocol not available"),
	       "ENOPROTOOPT → Protocol not available");
	ASSERT(!strcmp(strerror(EPROTONOSUPPORT), "Protocol not supported"),
	       "EPROTONOSUPPORT → Protocol not supported");
	ASSERT(!strcmp(strerror(ESOCKTNOSUPPORT), "Socket type not supported"),
	       "ESOCKTNOSUPPORT → Socket type not supported");
	ASSERT(!strcmp(strerror(ENOTSUP), "Operation not supported"),
	       "ENOTSUP → Operation not supported");
	ASSERT(!strcmp(strerror(EAFNOSUPPORT),
		       "Address family not supported by protocol"),
	       "EAFNOSUPPORT → Address family not supported by protocol");
	ASSERT(!strcmp(strerror(EADDRINUSE), "Address already in use"),
	       "EADDRINUSE → Address already in use");
	ASSERT(
	    !strcmp(strerror(EADDRNOTAVAIL), "Cannot assign requested address"),
	    "EADDRNOTAVAIL → Cannot assign requested address");
	ASSERT(!strcmp(strerror(ENETDOWN), "Network is down"),
	       "ENETDOWN → Network is down");
	ASSERT(!strcmp(strerror(ENETUNREACH), "Network is unreachable"),
	       "ENETUNREACH → Network is unreachable");
	ASSERT(
	    !strcmp(strerror(ECONNABORTED), "Software caused connection abort"),
	    "ECONNABORTED → Software caused connection abort");
	ASSERT(!strcmp(strerror(ECONNRESET), "Connection reset by peer"),
	       "ECONNRESET → Connection reset by peer");
	ASSERT(!strcmp(strerror(ENOBUFS), "No buffer space available"),
	       "ENOBUFS → No buffer space available");
	ASSERT(!strcmp(strerror(EISCONN),
		       "Transport endpoint is already connected"),
	       "EISCONN → Transport endpoint is already connected");
	ASSERT(
	    !strcmp(strerror(ENOTCONN), "Transport endpoint is not connected"),
	    "ENOTCONN → Transport endpoint is not connected");
	ASSERT(!strcmp(strerror(ESHUTDOWN),
		       "Cannot send after transport endpoint shutdown"),
	       "ESHUTDOWN → Cannot send after transport endpoint shutdown");
	ASSERT(!strcmp(strerror(ETIMEDOUT), "Connection timed out"),
	       "ETIMEDOUT → Connection timed out");
	ASSERT(!strcmp(strerror(ECONNREFUSED), "Connection refused"),
	       "ECONNREFUSED → Connection refused");
	ASSERT(!strcmp(strerror(EHOSTDOWN), "Host is down"),
	       "EHOSTDOWN → Host is down");
	ASSERT(!strcmp(strerror(EHOSTUNREACH), "No route to host"),
	       "EHOSTUNREACH → No route to host");
	ASSERT(!strcmp(strerror(EALREADY), "Operation already in progress"),
	       "EALREADY → Operation already in progress");
	ASSERT(!strcmp(strerror(EINPROGRESS), "Operation now in progress"),
	       "EINPROGRESS → Operation now in progress");
	ASSERT(!strcmp(strerror(EOVERFLOW),
		       "Value too large for defined data type"),
	       "EOVERFLOW → Value too large for defined data type");
	ASSERT(!strcmp(strerror(ECANCELED), "Operation Canceled"),
	       "ECANCELED → Operation Canceled");

	/* Aliases */
	ASSERT(
	    !strcmp(strerror(EWOULDBLOCK), "Resource temporarily unavailable"),
	    "EWOULDBLOCK → EAGAIN");
	ASSERT(!strcmp(strerror(EDEADLOCK), "Resource deadlock would occur"),
	       "EDEADLOCK → EDEADLK");

	/* Custom codes */
	ASSERT(!strcmp(strerror(EDUPLICATE), "Duplicate entry"),
	       "EDUPLICATE → Duplicate entry");
	ASSERT(!strcmp(strerror(ETODO), "Feature not implemented"),
	       "ETODO → Feature not implemented");

	/* Unknown / future codes */
	ASSERT(!strcmp(strerror(-1337), "Unknown error"),
	       "Negative unknown → Unknown error");
	ASSERT(!strcmp(strerror(99999), "Unknown error"),
	       "Large unknown → Unknown error");

	_debug_no_write = true;
	perror("test");
	_debug_no_write = false;
}

Test(errors2) {
	ASSERT(!strcmp(strerror(ENOMSG), "No message of desired type"),
	       "ENOMSG coverage");
	ASSERT(!strcmp(strerror(EIDRM), "Identifier removed"),
	       "EIDRM coverage");
	ASSERT(!strcmp(strerror(ECHRNG), "Channel number out of range"),
	       "ECHRNG coverage");
	ASSERT(!strcmp(strerror(EL2NSYNC), "Level 2 not synchronized"),
	       "EL2NSYNC coverage");
	ASSERT(!strcmp(strerror(EL3HLT), "Level 3 halted"), "EL3HLT coverage");
	ASSERT(!strcmp(strerror(EL3RST), "Level 3 reset"), "EL3RST coverage");
	ASSERT(!strcmp(strerror(ELNRNG), "Link number out of range"),
	       "ELNRNG coverage");
	ASSERT(!strcmp(strerror(EUNATCH), "Protocol driver not attached"),
	       "EUNATCH coverage");
	ASSERT(!strcmp(strerror(ENOCSI), "No CSI structure available"),
	       "ENOCSI coverage");
	ASSERT(!strcmp(strerror(EL2HLT), "Level 2 halted"), "EL2HLT coverage");
	ASSERT(!strcmp(strerror(EBADE), "Invalid exchange"), "EBADE coverage");
	ASSERT(!strcmp(strerror(EBADR), "Invalid request descriptor"),
	       "EBADR coverage");
	ASSERT(!strcmp(strerror(EXFULL), "Exchange full"), "EXFULL coverage");
	ASSERT(!strcmp(strerror(ENOANO), "No anode"), "ENOANO coverage");
	ASSERT(!strcmp(strerror(EBADRQC), "Invalid request code"),
	       "EBADRQC coverage");
	ASSERT(!strcmp(strerror(EBADSLT), "Invalid slot"), "EBADSLT coverage");
	ASSERT(!strcmp(strerror(EBFONT), "Bad font file format"),
	       "EBFONT coverage");
	ASSERT(!strcmp(strerror(ENOSTR), "Device not a stream"),
	       "ENOSTR coverage");
	ASSERT(!strcmp(strerror(ENODATA), "No data available"),
	       "ENODATA coverage");
	ASSERT(!strcmp(strerror(ETIME), "Timer expired"), "ETIME coverage");
	ASSERT(!strcmp(strerror(ENOSR), "Out of streams resources"),
	       "ENOSR coverage");
	ASSERT(!strcmp(strerror(ENONET), "Machine is not on the network"),
	       "ENONET coverage");
	ASSERT(!strcmp(strerror(ENOPKG), "Package not installed"),
	       "ENOPKG coverage");
	ASSERT(!strcmp(strerror(EREMOTE), "Object is remote"),
	       "EREMOTE coverage");
	ASSERT(!strcmp(strerror(ENOLINK), "Link has been severed"),
	       "ENOLINK coverage");
	ASSERT(!strcmp(strerror(EADV), "Advertise error"), "EADV coverage");
	ASSERT(!strcmp(strerror(ESRMNT), "Srmount error"), "ESRMNT coverage");
	ASSERT(!strcmp(strerror(ECOMM), "Communication error on send"),
	       "ECOMM coverage");
	ASSERT(!strcmp(strerror(EPROTO), "Protocol error"), "EPROTO coverage");
	ASSERT(!strcmp(strerror(EMULTIHOP), "Multihop attempted"),
	       "EMULTIHOP coverage");
	ASSERT(!strcmp(strerror(EDOTDOT), "RFS specific error"),
	       "EDOTDOT coverage");
	ASSERT(!strcmp(strerror(EBADMSG), "Not a data message"),
	       "EBADMSG coverage");
	ASSERT(!strcmp(strerror(ENOTUNIQ), "Name not unique on network"),
	       "ENOTUNIQ coverage");
	ASSERT(!strcmp(strerror(EBADFD), "File descriptor in bad state"),
	       "EBADFD coverage");
	ASSERT(!strcmp(strerror(EREMCHG), "Remote address changed"),
	       "EREMCHG coverage");
	ASSERT(!strcmp(strerror(ELIBACC),
		       "Can not access a needed shared library"),
	       "ELIBACC coverage");
	ASSERT(
	    !strcmp(strerror(ELIBBAD), "Accessing a corrupted shared library"),
	    "ELIBBAD coverage");
	ASSERT(!strcmp(strerror(ELIBSCN), ".lib section in a.out corrupted"),
	       "ELIBSCN coverage");
	ASSERT(!strcmp(strerror(ELIBMAX),
		       "Attempting to link in too many shared libraries"),
	       "ELIBMAX coverage");
	ASSERT(!strcmp(strerror(ELIBEXEC),
		       "Cannot exec a shared library directly"),
	       "ELIBEXEC coverage");
	ASSERT(!strcmp(strerror(EILSEQ), "Illegal byte sequence"),
	       "EILSEQ coverage");
	ASSERT(!strcmp(strerror(ERESTART),
		       "Interrupted system call should be restarted"),
	       "ERESTART coverage");
	ASSERT(!strcmp(strerror(ESTRPIPE), "Streams pipe error"),
	       "ESTRPIPE coverage");
	ASSERT(!strcmp(strerror(EUSERS), "Too many users"), "EUSERS coverage");

	ASSERT(!strcmp(strerror(ENETRESET),
		       "Network dropped connection because of reset"),
	       "ENETRESET coverage");
	ASSERT(!strcmp(strerror(ESTALE), "Stale file handle"),
	       "ESTALE coverage");
	ASSERT(!strcmp(strerror(EUCLEAN), "Structure needs cleaning"),
	       "EUCLEAN coverage");
	ASSERT(!strcmp(strerror(ENOTNAM), "Not a XENIX named type file"),
	       "ENOTNAM coverage");
	ASSERT(!strcmp(strerror(ENAVAIL), "No XENIX semaphores available"),
	       "ENAVAIL coverage");
	ASSERT(!strcmp(strerror(EISNAM), "Is a named type file"),
	       "EISNAM coverage");
	ASSERT(!strcmp(strerror(EREMOTEIO), "Remote I/O error"),
	       "EREMOTEIO coverage");
	ASSERT(!strcmp(strerror(EDQUOT), "Quota exceeded"), "EDQUOT coverage");
	ASSERT(!strcmp(strerror(ENOMEDIUM), "No medium found"),
	       "ENOMEDIUM coverage");
	ASSERT(!strcmp(strerror(EMEDIUMTYPE), "Wrong medium type"),
	       "EMEDIUMTYPE coverage");
	ASSERT(!strcmp(strerror(ENOKEY), "Required key not available"),
	       "ENOKEY coverage");
	ASSERT(!strcmp(strerror(EKEYEXPIRED), "Key has expired"),
	       "EKEYEXPIRED coverage");
	ASSERT(!strcmp(strerror(EKEYREVOKED), "Key has been revoked"),
	       "EKEYREVOKED coverage");
	ASSERT(!strcmp(strerror(EKEYREJECTED), "Key was rejected by service"),
	       "EKEYREJECTED coverage");

	ASSERT(!strcmp(strerror(EPFNOSUPPORT), "Protocol family not supported"),
	       "EPFNOSUPPORT coverage");
	ASSERT(!strcmp(strerror(ETOOMANYREFS),
		       "Too many references: cannot splice"),
	       "Too many references: cannot splice");
	ASSERT(__err_location(), "__err_location");
}

Test(memmove) {
	const u8 *test = "test";
	const u8 *test2 = "aaaaa";
	u8 out[1024] = {0};

	ASSERT(memcmp(out, test, 4), "memcmp ne");
	memcpy(out, test, 4);
	ASSERT(!memcmp(out, test, 4), "memcmp eq");
	memmove(out, test2, 5);
	ASSERT(!memcmp(out, test2, 5), "memcmp eq");
	memcpy(out + 5, "bbbbbbbb", 8);
	memmove(out + 5, out, 8);
	ASSERT(!memcmp(out, "aaa", 3), "memmove cmp");
}

void __stack_chk_fail(void);
void __stack_chk_guard(void);

Test(stack_fails) {
	_debug_no_write = true;
	_debug_no_exit = true;

	__stack_chk_fail();
	__stack_chk_guard();

	_debug_no_write = false;
	_debug_no_exit = false;
}

Test(syscall) {
	i32 pid = getpid();
	i32 ret = kill(pid, 0);
	i32 ret2 = kill(I32_MAX, 0);
	ASSERT(!ret, "our pid");
	ASSERT(ret2, "invalid pid");

	u64 v = get_heap_bytes();
	ASSERT_EQ(v, 0, "heap_bytes");

	ASSERT_EQ(mmap(NULL, 1024, 100, 100, 100, 100), MAP_FAILED,
		  "mmap fail");

	v = get_heap_bytes();
	ASSERT_EQ(v, 0, "heap bytes = 0");

	void *ptr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERT(ptr, "mmap");

	v = get_heap_bytes();
	ASSERT_EQ(v, PAGE_SIZE, "heap bytes = PAGE_SIZE");
	ASSERT(!munmap(ptr, PAGE_SIZE), "munmap");

	v = get_heap_bytes();
	ASSERT_EQ(v, 0, "heap bytes = 0 (munmap)");
}

Test(clone) {
	i32 pid, pid2;

	u64 *val = mmap(NULL, sizeof(u64), PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	ASSERT(val, "mmap");
	*val = 0;

	pid = fork();
	ASSERT(pid >= 0, "fork");
	if (!pid) {
		__aadd64(val, 1);
		while (1) yield();
	} else {
	}

	pid2 = fork();
	ASSERT(pid2 >= 0, "fork2");
	if (!pid2) {
		__aadd64(val, 1);
		while (1) yield();
	} else {
	}

	while (__aload64(val) != 2) yield();
	kill(pid, SIGKILL);
	kill(pid2, SIGKILL);
	munmap(val, sizeof(u64));
}

Test(open1) {
	struct statx st = {0};
	u64 size = 4097;
	unlink("/tmp/open1.dat");
	unlink("/tmp/open2.dat");

	errno = 0;
	i32 fd = open("/tmp/open1.dat", O_CREAT | O_RDWR, 0600);
	fdatasync(fd);
	ASSERT(fd > 0, "fd>0 1");
	ASSERT(!statx("/tmp/open1.dat", &st), "statx");
	ASSERT(!st.stx_size, "size=0");

	ASSERT(!fallocate(fd, size), "fallocate");

	pwrite(fd, "abc", 3, 5);
	fsync(fd);
	u8 buf[4] = {0};
	u8 cmp[4] = {0};
	cmp[1] = 'a';
	cmp[2] = 'b';
	cmp[3] = 'c';
	pread(fd, buf, 4, 4);
	ASSERT(!memcmp(buf, cmp, 4), "equal");

	close(fd);
	fd = open("/tmp/open2.dat", O_RDWR | O_CREAT, 0600);
	ASSERT(fd > 0, "fd>0 2");

	close(fd);
	unlink("/tmp/open1.dat");
	unlink("/tmp/open2.dat");
}

Test(gettime) {
	struct timespec ts = {0};
	ASSERT_EQ(clock_gettime(CLOCK_REALTIME, &ts), 0, "gettime");
}

bool sig_recv = false;
u64 *val = NULL;
void test_handler(i32 sig) {
	ASSERT_EQ(sig, SIGUSR1, "sigusr1");
	__aadd64(val, 1);
	sig_recv = true;
}

Test(signal) {
	val = mmap(NULL, sizeof(u64), PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	ASSERT(val, "mmap");
	*val = 0;

	struct rt_sigaction act = {0};
	i32 pid;
	act.k_sa_handler = test_handler;
	act.k_sa_flags = SA_RESTORER;
	act.k_sa_restorer = restorer;
	i32 v = rt_sigaction(SIGUSR1, &act, NULL, 8);
	ASSERT(!v, "rt_sigaction");
	if ((pid = fork()))
		kill(pid, SIGUSR1);
	else {
		while (!sig_recv) yield();
		exit_group(0);
	}
	i32 r = waitpid(pid);
	ASSERT(!r, "await");
	ASSERT_EQ(*val, 1, "val=1");
	munmap(val, sizeof(u64));
}

Test(exists) {
	ASSERT(exists("resources/akjv5.txt"), "akvj5.txt");
	ASSERT(!exists("resources/blah.txt"), "blah.txt");
}

Test(nanosleep) {
	i32 res;
	res = nsleep(150000000);
	ASSERT(!res, "nsleep");
	res = usleep(100000);
	ASSERT(!res, "usleep");
	res = usleep(U64_MAX / 1000);
	ASSERT_EQ(res, -1, "usleep overflow");
	res = nsleep(U64_MAX);
	ASSERT_EQ(res, -1, "nsleep overflow");
}

extern Async *__global_async;
Test(async_errs) {
	u8 buf[1];
	async_add_queue(__global_async);
	ASSERT_EQ(pwrite(2, "x", 1, 0), -1, "pwrite err");
	ASSERT_EQ(pread(0, buf, 1, 0), -1, "pread err");
	ASSERT_EQ(open("/tmp/abc", O_CREAT | O_RDONLY, 0600), -1, "open err");
	ASSERT_EQ(close(-1), -1, "close err");
	ASSERT_EQ(fallocate(2, 100), -1, "fallocate err");
	ASSERT_EQ(fsync(2), -1, "fsync err");
	ASSERT_EQ(fdatasync(2), -1, "fdatasync err");
	ASSERT_EQ(nsleep(0), -1, "nsleep err");
	ASSERT_EQ(usleep(0), -1, "usleep err");
	ASSERT_EQ(unlink("/tmp/abc"), -1, "unlink err");
	ASSERT_EQ(statx("/tmp/abc", NULL), -1, "statx err");
	ASSERT_EQ(waitpid(1), -1, "waitpid err");
	async_sub_queue(__global_async);
}

Test(secure_zero) {
	__attribute__((aligned(32))) u8 buf[32] = {1, 2, 3, 4};
	ASSERT(memcmp(buf, (u8[32]){0}, 32), "not zero");
	secure_zero32(buf);
	ASSERT(!memcmp(buf, (u8[32]){0}, 32), "not zero");
}

Test(map) {
	void *x;
	u64 c = cycle_counter();
	ASSERT(c, "cycle_counter");
	x = map(4096);
	ASSERT(x, "map");
	munmap(x, 4096);
	x = smap(4096);
	ASSERT(x, "smap");
	munmap(x, 4096);
	i32 fd = open("resources/akjv5.txt", O_CREAT | O_RDWR, 0600);
	ASSERT(fd > 0, "fd");
	x = fmap(fd, 4096, 0);
	ASSERT(x, "fmap");
	munmap(x, 4096);
	close(fd);
}

Test(write_num) {
	unlink("/tmp/write_num0");
	i32 fd = open("/tmp/write_num0", O_CREAT | O_RDWR, 0600);
	ASSERT(!write_num(fd, 0), "write_num");
	close(fd);
	unlink("/tmp/write_num0");
}

Test(openfds) {
	ASSERT(!get_open_fds(), "get open fds");
	i32 fd = open("/tmp/openfds", O_CREAT | O_RDWR, 0600);
	ASSERT_EQ(get_open_fds(), 1, "one open");
	close(fd);
	ASSERT(!get_open_fds(), "get open fds 0");
	open_fds_reset();
	ASSERT(!get_open_fds(), "get open fds 0");
}

Test(pwrite_pread_fail) {
	_debug_pwrite_fail = 0;
	ASSERT_EQ(pwrite(2, "x\n", 2, 0), -1, "pwrite err");
	_debug_pwrite_fail = I64_MAX;

	_debug_pread_fail = 0;
	u8 buf[2];
	ASSERT_EQ(pread(0, buf, 2, 0), -1, "pread err");
	_debug_pread_fail = I64_MAX;
}

Test(open) {
	u8 buf[1024] = {0};
	i32 fd;
	const u8 *path = "/tmp/open_test1.dat";
	unlink(path);
	ASSERT_EQ(open(path, O_RDONLY, 0), -1, "not exist");
	fd = open(path, O_CREAT | O_RDWR, 0700);
	ASSERT(fd > 0, "fd");
	ASSERT_EQ(pwrite(fd, "abc", 3, 0), 3, "pwrite");
	close(fd);
	fd = open(path, O_RDONLY, 0);
	ASSERT(fd > 0, "rdonly");
	ASSERT_EQ(pread(fd, buf, 3, 0), 3, "pread");
	ASSERT(!memcmp(buf, "abc", 3), "eq");
	ASSERT_EQ(pwrite(fd, "xyz", 3, 0), -1, "perm");
	close(fd);
	fd = open(path, O_RDWR, 0);
	ASSERT(fd > 0, "rdwr");
	ASSERT_EQ(pread(fd, buf, 3, 0), 3, "pread");
	ASSERT(!memcmp(buf, "abc", 3), "eq");
	ASSERT_EQ(pwrite(fd, "xyz", 3, 0), 3, "pwrite rdwr");
	ASSERT_EQ(pread(fd, buf, 3, 0), 3, "pread");
	ASSERT(!memcmp(buf, "xyz", 3), "eq");
	close(fd);
	unlink(path);
}

i32 complete_counter = 0;

void on_complete(i32 res, u64 user_data, void *ctx) {
	ASSERT_EQ(user_data, 123, "user_data");
	ASSERT(res > 0, "new fd");
	ASSERT(!ctx, "ctx");
	__aadd64(&open_fds, 1);
	close(res);
	complete_counter++;
}

Test(async) {
	u32 count;
	struct open_how how = {.flags = O_CREAT | O_RDWR, .mode = 0600};
	Async *async = NULL;
	struct io_uring_sqe sqe1 = {
	    .opcode = IORING_OP_OPENAT2,
	    .fd = AT_FDCWD,
	    .addr = (u64) "/tmp/async.dat",
	    .len = sizeof(struct open_how),
	    .off = (u64)&how,
	    .user_data = 123,
	};

	unlink("/tmp/async.dat");
	ASSERT(!exists("/tmp/async.dat"), "!exists");
	ASSERT(!async_init(&async, 8, on_complete, NULL), "async_init");
	ASSERT(async, "async");
	count = async_execute(async, (struct io_uring_sqe[]){sqe1}, 1, true);
	ASSERT_EQ(complete_counter, 1, "callback");
	ASSERT_EQ(count, 1, "count");
	ASSERT(exists("/tmp/async.dat"), "exists");
	async_destroy(async);
	unlink("/tmp/async.dat");
}

u32 chain_status = 0;
i32 chain_fd = 0;

typedef struct {
	Async *async;
} AsyncHolder;

void chain_complete(i32 res, u64 user_data, void *ctx) {
	AsyncHolder *holder = ctx;
	if (user_data == 123) {
		chain_fd = res;
		struct io_uring_sqe sqe1 = {
		    .opcode = IORING_OP_FALLOCATE,
		    .fd = res,
		    .addr = 4096,
		    .user_data = 124,
		};

		async_execute(holder->async, (struct io_uring_sqe[]){sqe1}, 1,
			      false);
	} else {
		chain_status = 1;
	}
}

Test(async_chain) {
	AsyncHolder holder;
	struct open_how how = {.flags = O_CREAT | O_RDWR, .mode = 0600};
	Async *async = NULL;
	struct io_uring_sqe sqe1 = {
	    .opcode = IORING_OP_OPENAT2,
	    .fd = AT_FDCWD,
	    .addr = (u64) "/tmp/async_chain.dat",
	    .len = sizeof(struct open_how),
	    .off = (u64)&how,
	    .user_data = 123,
	};

	unlink("/tmp/async_chain.dat");
	ASSERT(!exists("/tmp/async_chain.dat"), "!exists");
	ASSERT(!async_init(&async, 8, chain_complete, &holder), "async_init");
	holder.async = async;
	ASSERT(async, "async");
	async_execute(async, (struct io_uring_sqe[]){sqe1}, 1, false);
	while (!chain_status) async_execute(async, NULL, 0, true);
	ASSERT(exists("/tmp/async_chain.dat"), "exists");

	struct statx st = {0};

	statx("/tmp/async_chain.dat", &st);
	ASSERT_EQ(st.stx_size, 4096, "size=4096");

	close(chain_fd);
	__aadd64(&open_fds, 1);

	async_destroy(async);
	unlink("/tmp/async_chain.dat");
}

Test(async_errors) {
	Async *async;
	ASSERT_EQ(async_init(&async, U32_MAX, chain_complete, NULL), -1,
		  "queue too large");

	_debug_alloc_count = 0;
	ASSERT_EQ(async_init(&async, 1, chain_complete, NULL), -1, "alloc0");
	_debug_alloc_count = I64_MAX;

	_debug_alloc_count = 1;
	ASSERT_EQ(async_init(&async, 1, chain_complete, NULL), -1, "alloc1");
	_debug_alloc_count = I64_MAX;

	_debug_alloc_count = 2;
	ASSERT_EQ(async_init(&async, 1, chain_complete, NULL), -1, "alloc2");
	_debug_alloc_count = I64_MAX;

	_debug_alloc_count = 3;
	ASSERT_EQ(async_init(&async, 1, chain_complete, NULL), -1, "alloc3");
	_debug_alloc_count = I64_MAX;

	ASSERT(!async_init(&async, 1, chain_complete, NULL), "init success");
	ASSERT_EQ(async_execute(async, NULL, 2, false), -1, "queue too big");
	async_destroy(async);
}

Test(misc) {
	struct statx st = {0};
	unlink("/tmp/misc1");
	i32 f1 = open("/tmp/misc1", O_CREAT | O_RDWR, 0600);
	ASSERT(fchmod(f1, 0777) >= 0, "fchmod");
	statx("/tmp/misc1", &st);
	struct timeval ts[2] = {0};
	ts[0].tv_sec = st.stx_atime.tv_sec - 1;
	ts[1].tv_sec = st.stx_mtime.tv_sec - 1;
	ASSERT(!utimesat(f1, NULL, ts, 0), "utimesat");
	unlink("/tmp/misc1");
	ASSERT_EQ(io_uring_register(-1, 0, NULL, 0), -1, "reg err");
	close(f1);
	ASSERT_EQ(munmap((void *)1, 1), -1, "invalid unmap");
}
