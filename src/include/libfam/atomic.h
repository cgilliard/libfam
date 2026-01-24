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

#ifndef _ATOMIC_H
#define _ATOMIC_H

#include <libfam/types.h>

static __inline i32 __cas32(u32 *ptr, u32 *expected, u32 desired) {
	return __atomic_compare_exchange(ptr, expected, &desired, false,
					 __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
}

static __inline u32 __aand32(volatile u32 *ptr, u32 value) {
	return __atomic_fetch_and(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline u32 __aadd32(volatile u32 *ptr, u32 value) {
	return __atomic_fetch_add(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline u32 __asub32(volatile u32 *ptr, u32 value) {
	return __aadd32(ptr, -value);
}

static __inline u32 __aor32(volatile u32 *ptr, u32 value) {
	return __atomic_fetch_or(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline i32 __cas64(u64 *ptr, u64 *expected, u64 desired) {
	return __atomic_compare_exchange(ptr, expected, &desired, false,
					 __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
}

static __inline u64 __aand64(volatile u64 *ptr, u64 value) {
	return __atomic_fetch_and(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline u64 __aadd64(volatile u64 *ptr, u64 value) {
	return __atomic_fetch_add(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline u64 __asub64(volatile u64 *ptr, u64 value) {
	return __aadd64(ptr, -value);
}

static __inline u64 __aor64(volatile u64 *ptr, u64 value) {
	return __atomic_fetch_or(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline u32 __aload32(const volatile u32 *ptr) {
	return __atomic_load_n(ptr, __ATOMIC_SEQ_CST);
}

static __inline u64 __aload64(const volatile u64 *ptr) {
	return __atomic_load_n(ptr, __ATOMIC_SEQ_CST);
}

static __inline void __astore32(volatile u32 *ptr, u32 value) {
	__atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline void __astore64(volatile u64 *ptr, u64 value) {
	__atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}

static __inline i32 __cas128(u128 *ptr, u128 *expected, u128 desired) {
#ifdef __x86_64__
	u64 exp_lo = (u64)(*expected);
	u64 exp_hi = (u64)(*expected >> 64);
	u64 des_lo = (u64)desired;
	u64 des_hi = (u64)(desired >> 64);
	u8 success;

	__asm__ volatile(
	    "lock cmpxchg16b %[ptr]\n\t"
	    "sete    %[success]"
	    : [success] "=qm"(success), [ptr] "+m"(*ptr), "+A"(exp_lo),
	      "+d"(exp_hi)
	    : "b"(des_lo), "c"(des_hi)
	    : "memory", "cc");

	if (!success) *expected = ((u128)exp_hi << 64) | exp_lo;

	return success;
#elif defined(__aarch64__)
	i32 __cas128_arm64(u128 * ptr, u128 * expected, u128 desired);
	return __cas128_arm64(ptr, expected, desired);
#else
#error "Unsupported Platform"
#endif /* !__aarch64__ */
}

static inline u128 __aload128(volatile u128 *ptr) {
#ifdef __x86_64__
	u64 lo, hi;
	__asm__ volatile(
	    "movq    %%rax, %%rbx\n\t"
	    "movq    %%rdx, %%rcx\n\t"
	    "lock cmpxchg16b %[ptr]\n\t"
	    : "=A"(lo), "=d"(hi), [ptr] "+m"(*ptr)
	    : "a"(0), "d"(0)
	    : "rbx", "rcx", "memory", "cc");
	return ((u128)hi << 64) | lo;
#elif defined(__aarch64__)
	static inline u128 __aload128(const volatile u128 *ptr) {
		u64 lo, hi;

		__asm__ volatile(
		    "ldxp    %[lo], %[hi], [%[ptr]]\n\t"
		    "dmb     sy\n\t"
		    : [lo] "=r"(lo), [hi] "=r"(hi)
		    : [ptr] "Q"(*ptr)
		    : "memory");

		return ((u128)hi << 64) | lo;
	}
#endif /* __aarch64__ */
}

static __inline void mfence(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }

#endif /* _ATOMIC_H */
