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
#include <libfam/format.h>
#include <libfam/hashtable.h>
#include <libfam/limits.h>
#include <libfam/lru.h>
#include <libfam/rbtree.h>
#include <libfam/rng.h>
#include <libfam/string.h>
#include <libfam/test.h>

Test(string_u128) {
	u128 i;
	u128 v1 = 1234;
	i128 v2 = -5678;
	u8 buf[MAX_I128_STRING_LEN];
	ASSERT(u128_to_string(buf, v1, Int128DisplayTypeDecimal) > 0,
	       "u128_to_string");
	ASSERT(!strcmp(buf, "1234"), "1234");

	ASSERT(i128_to_string(buf, v2, Int128DisplayTypeDecimal) > 0,
	       "i128_to_string");
	ASSERT(!strcmp(buf, "-5678"), "-5678");

	for (i = 0; i < 100000 * 10000; i += 10000) {
		u128 v = i;
		u128 vout;
		u128_to_string(buf, v, Int128DisplayTypeDecimal);
		string_to_u128(buf, strlen(buf), &vout);
		ASSERT_EQ(v, vout, "v=vout");
	}

	ASSERT_EQ(i128_to_string(buf, 0x123, Int128DisplayTypeHexUpper), 5,
		  "len=5");
	ASSERT(!strcmp(buf, "0x123"), "string 0x123");

	ASSERT_EQ(i128_to_string(buf, 0xF, Int128DisplayTypeBinary), 4,
		  "binary 0xF");
	ASSERT(!strcmp(buf, "1111"), "string 1111");

	ASSERT(u128_to_string(buf, 9993, Int128DisplayTypeCommas) > 0,
	       "commas");
	ASSERT(!strcmp(buf, "9,993"), "comma verify");
}

u128 __umodti3(u128 a, u128 b);
u128 __udivti3(u128 a, u128 b);

/*
Test(stubs) {
	u128 v1 = (u128)111 << 77;
	u128 v2 = (u128)333 << 77;
	ASSERT_EQ(__umodti3(v2, v1), 0, "umod0");
	v1 = 1;
	v2 = (u128)U64_MAX + 1;
	ASSERT_EQ(__umodti3(v2, v1), 0, "umod1");
}
*/

Test(stubs) {
	u128 v1 = (u128)111 << 77;
	u128 v2 = (u128)333 << 77;
	ASSERT_EQ(__umodti3(v2, v1), 0, "umod0");

	v1 = 1;
	v2 = (u128)U64_MAX + 1;
	ASSERT_EQ(__umodti3(v2, v1), 0, "umod1");

	ASSERT_EQ(__udivti3(100, 7), 14, "div_small1");
	ASSERT_EQ(__umodti3(100, 7), 2, "mod_small1");

	ASSERT_EQ(__udivti3(123456789ULL, 12345), 10000, "div_small2");
	ASSERT_EQ(__umodti3(123456789ULL, 12345), 6789, "mod_small2");

	ASSERT_EQ(__udivti3(0xFFFFFFFFFFFFFFFFULL, 1), 0xFFFFFFFFFFFFFFFFULL,
		  "div_by_1");
	ASSERT_EQ(__umodti3(0xFFFFFFFFFFFFFFFFULL, 1), 0, "mod_by_1");

	ASSERT_EQ(__udivti3(0, 42), 0, "div_zero");
	ASSERT_EQ(__umodti3(0, 42), 0, "mod_zero");

	u128 max = (u128)~0ULL;
	ASSERT_EQ(__udivti3(max, max), 1, "div_max_max");
	ASSERT_EQ(__umodti3(max, max), 0, "mod_max_max");

	ASSERT_EQ(__udivti3(max, 1), max, "div_max_1");
	ASSERT_EQ(__umodti3(max, 1), 0, "mod_max_1");

	u128 pow2_64 = (u128)1 << 64;
	ASSERT_EQ(__udivti3(pow2_64, (u128)1 << 32), (u128)1 << 32,
		  "div_pow2_1");
	ASSERT_EQ(__umodti3(pow2_64, (u128)1 << 32), 0, "mod_pow2_1");

	ASSERT_EQ(__udivti3(max, (u128)1 << 70), max >> 70, "div_max_pow2");
	ASSERT_EQ(__umodti3(max, (u128)1 << 70), max & (((u128)1 << 70) - 1),
		  "mod_max_pow2");

	u128 a = ((u128)1 << 70) + 0x123456789ABCDEF0ULL;
	u128 b = (u128)0xFEDCBA9876543210ULL;
	u128 expected_q = a / b;
	u128 expected_r = a % b;
	ASSERT_EQ(__udivti3(a, b), expected_q, "div_high_bits");
	ASSERT_EQ(__umodti3(a, b), expected_r, "mod_high_bits");

	u128 big_divisor = ((u128)1 << 64) + 12345;
	u128 multiple = big_divisor * 1000;
	ASSERT_EQ(__udivti3(multiple, big_divisor), 1000,
		  "div_big_divisor_exact");
	ASSERT_EQ(__umodti3(multiple, big_divisor), 0, "mod_big_divisor_exact");

	ASSERT_EQ(__umodti3(1000, 999), 1, "mod_large_remainder");
	ASSERT_EQ(__udivti3(1000, 999), 1, "div_large_remainder");

	ASSERT_EQ(__udivti3(7, 8), 0, "div_small_divisor_larger");
	ASSERT_EQ(__umodti3(7, 8), 7, "mod_small_divisor_larger");
}

Test(stubs2) {
	u128 a = (u128)0xFFFFFFFFFFFFFFFF << 64 | 0xFFFFFFFFFFFFFFFF;
	u128 b = (u128)0x8000000000000000ULL;
	u128 c;
	u128 x = a % b;
	ASSERT_EQ(x, 9223372036854775807, "9223372036854775807");
	a = (u128)0xFFFFFFFFFFFFFFFF << 64 | 0xFFFFFFFFFFFFFFFF;
	b = (u128)0xFFFFFFFFFFFFFFFFULL;
	x = a % b;
	ASSERT(!x, "x=0");
	a = (u128)0x0000000100000000 << 64 | 0xFFFFFFFFFFFFFFFF;
	b = (u128)0x0000000100000001ULL;
	x = a % b;
	ASSERT_EQ(x, 4294967296, "x=4294967296");
	a = ((u128)0xFFFFFFFF00000000ULL << 64) | 0xFFFFFFFFFFFFFFFFULL;
	b = 0xFFFFFFFF80000000ULL;
	x = a % b;
	ASSERT_EQ(x, 13835058055282163711ULL, "x=13835058055282163711");

	a = 12345;
	b = 123;
	c = a / b;
	ASSERT_EQ(c, 100, "100");
	a = ((u128)0x1) << 70;
	b = 1;
	c = a / b;
	ASSERT_EQ(c, a, "c=a");

	a = 1;
	b = ((u128)0x1) << 70;
	c = a / b;
	ASSERT(!c, "c=0");
}

Test(strstr) {
	const char *s = "abcdefghi";
	ASSERT_EQ(strstr(s, "def"), s + 3, "strstr1");
	ASSERT_EQ(strstr(s, "x"), NULL, "no match");
	ASSERT_EQ(get_heap_bytes(), 0, "heap bytes");
}

Test(format1) {
	Formatter f = FORMATTER_INIT;
	FORMAT(&f, "{}", 1);
	ASSERT(!strcmp("1", format_to_string(&f)), "1");
	format_clear(&f);
	FORMAT(&f, "{}", -1);
	ASSERT(!strcmp("-1", format_to_string(&f)), "-1");
	format_clear(&f);
	FORMAT(&f, "x={x}", 0xFE);
	ASSERT(!strcmp("x=0xfe", format_to_string(&f)), "x=0xfe");
	format_clear(&f);
	FORMAT(&f, "x={X},...", 255);
	ASSERT(!strcmp("x=0xFF,...", format_to_string(&f)), "x=0xFF,...");
	format_clear(&f);
	FORMAT(&f, "a={},b={},c={},d={x}", "test", 1.23456, 9999, 253);
	ASSERT(!strcmp("a=test,b=1.23456,c=9999,d=0xfd", format_to_string(&f)),
	       "multi");
	format_clear(&f);
	FORMAT(&f, "a={c},b={b} {nothing", (u8)'a', 3);
	ASSERT(!strcmp("a=a,b=11 {nothing", format_to_string(&f)),
	       "char and bin");
	format_clear(&f);
	u64 x = 101;
	FORMAT(&f, "{}", x);
	ASSERT(!strcmp("101", format_to_string(&f)), "101");
	format_clear(&f);
	FORMAT(&f, "{n}", 1001);
	ASSERT(!strcmp("1,001", format_to_string(&f)), "101 commas");
	format_clear(&f);
	FORMAT(&f, "x=${n.2}", 1234567.930432);
	ASSERT(!strcmp("x=$1,234,567.93", format_to_string(&f)),
	       "dollar format");
	format_clear(&f);
	ASSERT_BYTES(0);
}

Test(format2) {
	Formatter f = FORMATTER_INIT;
	FORMAT(&f, "'{:5x}'", 10);
	ASSERT(!strcmp("'  0xa'", format_to_string(&f)), "alignment hex");
	format_clear(&f);
	FORMAT(&f, "'{{' {}", 10);
	ASSERT(!strcmp("'{' 10", format_to_string(&f)), "esc bracket left");
	format_clear(&f);
	FORMAT(&f, "'}}' {n}", 1000);
	ASSERT(!strcmp("'}' 1,000", format_to_string(&f)),
	       "esc bracket right and commas");
	format_clear(&f);
	FORMAT(&f, "{nn}", 10);
	ASSERT(!strcmp("{nn}", format_to_string(&f)), "formatting error");
	format_clear(&f);
	FORMAT(&f, "'{:<20}'", 10);
	ASSERT(!strcmp("'10                  '", format_to_string(&f)),
	       "formatting error");
	format_clear(&f);
	FORMAT(&f, "'{:>20}'", 10);
	ASSERT(!strcmp("'                  10'", format_to_string(&f)),
	       "formatting error");
	format_clear(&f);
	FORMAT(&f, "{n{}", 10);
	ASSERT(!strcmp("{n{}", format_to_string(&f)), "formatting error - int");
	format_clear(&f);
	i8 x = 'v';
	FORMAT(&f, "{c}", x);
	ASSERT(!strcmp("v", format_to_string(&f)), "i8 as char");
	format_clear(&f);
	FORMAT(&f, "{z}", "abc");
	ASSERT(!strcmp("{z}", format_to_string(&f)),
	       "formatting error - string");
	format_clear(&f);
	Printable p = {.t = 100, .data.ivalue = 100};
	format_append(&f, "{}", p);
	ASSERT(!strcmp("", format_to_string(&f)),
	       "formatting error - invalid type");
	format_clear(&f);
	_debug_alloc_count = 0;
	FORMAT(&f, "{}", "abc");
	_debug_alloc_count = I64_MAX;
	ASSERT(!strcmp(format_to_string(&f), ""), "alloc failure1");
	format_clear(&f);
	_debug_alloc_count = 0;
	FORMAT(&f, "{{");
	_debug_alloc_count = I64_MAX;

	ASSERT(!strcmp(format_to_string(&f), ""), "alloc failure2");
	format_clear(&f);
	_debug_alloc_count = 0;
	FORMAT(&f, "}}");
	_debug_alloc_count = I64_MAX;

	ASSERT(!strcmp(format_to_string(&f), ""), "alloc failure3");
	format_clear(&f);
}

Test(lru_cache) {
	LruCache *cache = lru_init(1024, 2048, sizeof(u64));
	ASSERT(cache, "cache");
	u64 value = 2;
	lru_put(cache, 1, &value);
	ASSERT_EQ(lru_get(cache, 2), NULL, "cache not found");
	u64 *x = lru_get(cache, 1);
	ASSERT_EQ(*x, 2, "cache found");
	lru_destroy(cache);
}

Test(lru_cache_cycle) {
	LruCache *cache = lru_init(256, 512, sizeof(u64));

	ASSERT(cache, "cache");
	for (u64 i = 0; i < 256; i++) {
		u64 x = i + 1000;
		lru_put(cache, i, &x);
	}
	for (u64 i = 0; i < 256; i++) {
		u64 *value = lru_get(cache, i);
		ASSERT(value, "found {}", i);
		ASSERT_EQ(*value, i + 1000, "value {}", i);
	}

	u64 x = 1256;
	lru_put(cache, 256, &x);

	ASSERT(!lru_get(cache, 0), "evicted");
	x = 1001;
	ASSERT(!memcmp(lru_get(cache, 1), &x, sizeof(u64)), "not evicted");

	x = 2000;
	lru_put(cache, 1000, &x);
	ASSERT(!lru_get(cache, 2), "evicted");
	x = 1001;
	ASSERT(!memcmp(lru_get(cache, 1), &x, sizeof(u64)), "not evicted");
	x = 1003;
	ASSERT(!memcmp(lru_get(cache, 3), &x, sizeof(u64)), "not evicted");

	lru_destroy(cache);
}

typedef struct {
	RbTreeNode _reserved;
	u64 key;
	u64 value;
} KeyValue;

static i32 lru_cache_search(RbTreeNode *cur, const RbTreeNode *value,
			    RbTreeNodePair *retval) {
	while (cur) {
		u64 v1 = ((KeyValue *)cur)->key;
		u64 v2 = ((KeyValue *)value)->key;
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

Test(lru_cache_consistent) {
	RbTree tree = RBTREE_INIT;

	LruCache *cache = lru_init(1024, 512, sizeof(u64));
	Rng rng;

	rng_init(&rng);
	KeyValue arr[4096 + 1024] = {0};

	for (u32 i = 0; i < 4096; i++) {
		u64 key = 0;
		u64 value = 0;
		KeyValue kv;
		RbTreeNodePair retval;
		do {
			memset(&retval, 0, sizeof(RbTreeNodePair));
			rng_gen(&rng, &key, sizeof(u64));
			rng_gen(&rng, &value, sizeof(u64));
			kv.key = key;
			kv.value = value;
			lru_cache_search(tree.root, (RbTreeNode *)&kv, &retval);
		} while (retval.self && ((KeyValue *)retval.self)->key == key);
		KeyValue *kvmap = &arr[i];
		kvmap->key = key;
		kvmap->value = value;
		rbtree_put(&tree, (RbTreeNode *)kvmap, lru_cache_search);
		lru_put(cache, key, &value);
	}

	for (u32 i = 0; i < 1024; i++) {
		u64 key = 0;
		u64 value = 0;
		KeyValue kv;
		RbTreeNodePair retval;
		do {
			memset(&retval, 0, sizeof(RbTreeNodePair));
			rng_gen(&rng, &key, sizeof(u64));
			rng_gen(&rng, &value, sizeof(u64));
			kv.key = key;
			kv.value = value;
			lru_cache_search(tree.root, (RbTreeNode *)&kv, &retval);
		} while (retval.self && ((KeyValue *)retval.self)->key == key);
		KeyValue *kvmap = &arr[i + 4096];
		kvmap->key = key;
		kvmap->value = value;
		rbtree_put(&tree, (RbTreeNode *)kvmap, lru_cache_search);
		lru_put(cache, key, &value);
	}

	for (u32 i = 0; i < 4096; i++) {
		void *value = lru_get(cache, arr[i].key);
		ASSERT(!value, "!value");
	}
	for (u32 i = 4096; i < 4096 + 1024; i++) {
		u64 *value = lru_get(cache, arr[i].key);
		ASSERT_EQ(*value, arr[i].value, "found");
	}

	// bring 4999/5000 to front
	lru_get(cache, arr[4999].key);
	lru_get(cache, arr[5000].key);

	for (u32 i = 0; i < 1023; i++) {
		u64 key = 0, value = 0;
		do {
			rng_gen(&rng, &key, sizeof(u64));
			rng_gen(&rng, &value, sizeof(u64));
		} while (lru_get(cache, key));
		lru_put(cache, key, &value);
	}
	ASSERT(!lru_get(cache, arr[4999].key), "evicted");
	u64 *check = lru_get(cache, arr[5000].key);
	ASSERT_EQ(*check, arr[5000].value, "found");

	lru_destroy(cache);
}

Test(hashtable) {
	u64 key;
	u32 value;
	u8 kv1[HASHTABLE_KEY_VALUE_OVERHEAD + sizeof(u64) + sizeof(u32)];
	u8 kv2[HASHTABLE_KEY_VALUE_OVERHEAD + sizeof(u64) + sizeof(u32)];
	Hashtable *h = hashtable_init(512, sizeof(u64), sizeof(u32));
	ASSERT(h, "hashtable_init");
	key = 123;
	value = 456;
	fastmemcpy(kv1 + sizeof(HashtableKeyValue), &key, sizeof(u64));
	fastmemcpy(kv1 + sizeof(HashtableKeyValue) + sizeof(u64), &value,
		   sizeof(u32));
	hashtable_put(h, (HashtableKeyValue *)kv1);
	key = 999;
	value = 1010;
	fastmemcpy(kv2 + sizeof(HashtableKeyValue), &key, sizeof(u64));
	fastmemcpy(kv2 + sizeof(HashtableKeyValue) + sizeof(u64), &value,
		   sizeof(u32));
	hashtable_put(h, (HashtableKeyValue *)kv2);

	key = 123;
	u32 *vout = hashtable_get(h, &key);
	ASSERT_EQ(*vout, 456, "hashtable_get");

	key = 999;
	vout = hashtable_get(h, &key);
	ASSERT_EQ(*vout, 1010, "hashtable_get2");

	key = 998;
	vout = hashtable_get(h, &key);
	ASSERT(!vout, "not found");

	ASSERT(!hashtable_remove(h, &key), "remove null");
	key = 999;
	void *res = hashtable_remove(h, &key);
	ASSERT(res, "found");
	u64 *k1 = (void *)((u8 *)res + sizeof(HashtableKeyValue));
	ASSERT_EQ(*k1, 999, "key");
	u32 *v1 = (void *)((u8 *)res + sizeof(HashtableKeyValue) + sizeof(u64));
	ASSERT_EQ(*v1, 1010, "value");

	ASSERT(!hashtable_get(h, &key), "key not found");

	hashtable_destroy(h);
}
