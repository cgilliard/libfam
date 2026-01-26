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

#include <libfam/famdb_manip.h>
#include <libfam/rbtree.h>
#include <libfam/rng.h>
#include <libfam/test.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif /* PAGE_SIZE */

Test(famdb_manip) {
	u8 page[PAGE_SIZE] = {0};
	ASSERT(PAGE_IS_LEAF(page), "is leaf");
	ASSERT(!PAGE_IS_INTERNAL(page), "is int");
	ASSERT(!PAGE_ELEMENTS(page), "no elems");
	ASSERT(!PAGE_TOTAL_BYTES(page), "no bytes");
	LEAF_INSERT_AT(page, 512, 0, "abcd", 4, "ghij", 4);
	ASSERT(PAGE_IS_LEAF(page), "is leaf");
	ASSERT_EQ(PAGE_ELEMENTS(page), 1, "1 elem");
	ASSERT_EQ(PAGE_TOTAL_BYTES(page), (4 + 4 + 4 + 2), "total bytes");
	ASSERT(!memcmp(LEAF_READ_KEY(page, 0), "abcd", LEAF_KEY_LEN(page, 0)),
	       "key");
	ASSERT_EQ(PAGE_OFFSET_OF(page, 0), 512, "offset");
	ASSERT_EQ(LEAF_ENTRY_LEN(page, 0), (4 + 4), "entry len");
	ASSERT_EQ(LEAF_VALUE_LEN(page, 0), 4, "value len");
	ASSERT(
	    !memcmp(LEAF_READ_VALUE(page, 0), "ghij", LEAF_VALUE_LEN(page, 0)),
	    "value");
	LEAF_INSERT_AT(page, 512, 0, "xxx", 3, "0123456", 7);

	ASSERT_EQ(LEAF_KEY_LEN(page, 0), 3, "klen");
	ASSERT(!memcmp(LEAF_READ_KEY(page, 0), "xxx", LEAF_KEY_LEN(page, 0)),
	       "key");
	ASSERT_EQ(LEAF_VALUE_LEN(page, 0), 7, "vlen");

	ASSERT(!memcmp(LEAF_READ_VALUE(page, 0), "0123456",
		       LEAF_VALUE_LEN(page, 0)),
	       "value");

	ASSERT_EQ(PAGE_ELEMENTS(page), 2, "elements = 2");
	ASSERT_EQ(PAGE_TOTAL_BYTES(page), (4 + 4 + 4 + 2) + (3 + 7 + 4 + 2),
		  "total bytes (2 ent)");

	ASSERT_EQ(LEAF_KEY_LEN(page, 1), 4, "elem2.len=4");

	ASSERT(!memcmp(LEAF_READ_KEY(page, 1), "abcd", LEAF_KEY_LEN(page, 1)),
	       "key");
	ASSERT(
	    !memcmp(LEAF_READ_VALUE(page, 1), "ghij", LEAF_VALUE_LEN(page, 1)),
	    "value");

	LEAF_INSERT_AT(page, 512, 2, "0123456789", 10, "11111", 5);

	ASSERT(!memcmp(LEAF_READ_VALUE(page, 0), "0123456",
		       LEAF_VALUE_LEN(page, 0)),
	       "value");

	ASSERT(!memcmp(LEAF_READ_KEY(page, 1), "abcd", LEAF_KEY_LEN(page, 1)),
	       "key");
	ASSERT(
	    !memcmp(LEAF_READ_VALUE(page, 1), "ghij", LEAF_VALUE_LEN(page, 1)),
	    "value");

	ASSERT(!memcmp(LEAF_READ_KEY(page, 2), "0123456789",
		       LEAF_KEY_LEN(page, 2)),
	       "key");
	ASSERT(
	    !memcmp(LEAF_READ_VALUE(page, 2), "11111", LEAF_VALUE_LEN(page, 2)),
	    "value");

	ASSERT_EQ(PAGE_ELEMENTS(page), 3, "elements = 3");
	ASSERT_EQ(PAGE_TOTAL_BYTES(page),
		  (4 + 4 + 4 + 2) + (3 + 7 + 4 + 2) + (10 + 5 + 4 + 2),
		  "total bytes (3 ent)");

	LEAF_INSERT_AT(page, 512, 1, "999999", 6, "111", 3);

	ASSERT(!memcmp(LEAF_READ_VALUE(page, 0), "0123456",
		       LEAF_VALUE_LEN(page, 0)),
	       "value");

	ASSERT(!memcmp(LEAF_READ_KEY(page, 1), "999999", LEAF_KEY_LEN(page, 1)),
	       "keyx");

	ASSERT(
	    !memcmp(LEAF_READ_VALUE(page, 1), "111", LEAF_VALUE_LEN(page, 1)),
	    "value");

	ASSERT(!memcmp(LEAF_READ_KEY(page, 2), "abcd", LEAF_KEY_LEN(page, 2)),
	       "key2");

	ASSERT(
	    !memcmp(LEAF_READ_VALUE(page, 2), "ghij", LEAF_VALUE_LEN(page, 2)),
	    "value2");

	ASSERT(!memcmp(LEAF_READ_KEY(page, 3), "0123456789",
		       LEAF_KEY_LEN(page, 3)),
	       "key3");

	ASSERT(
	    !memcmp(LEAF_READ_VALUE(page, 3), "11111", LEAF_VALUE_LEN(page, 3)),
	    "value3");

	ASSERT_EQ(PAGE_ELEMENTS(page), 4, "elements = 4");
	ASSERT_EQ(PAGE_TOTAL_BYTES(page),
		  (4 + 4 + 4 + 2) + (3 + 7 + 4 + 2) + (10 + 5 + 4 + 2) +
		      (6 + 3 + 4 + 2),
		  "total bytes (4 ent)");
}

Test(famdb_rand) {
#define TRIALS 32
#define MAX_KEY_LEN 32
#define MAX_VALUE_LEN 64
	u8 page[PAGE_SIZE] = {0};
	Rng rng;
	u64 total_bytes = 0;
	__attribute__((aligned(32))) u8 keys[TRIALS][MAX_KEY_LEN] = {0};
	__attribute__((aligned(32))) u8 values[TRIALS][MAX_VALUE_LEN] = {0};
	__attribute__((aligned(32))) u8 klens[TRIALS] = {0};
	__attribute__((aligned(32))) u8 vlens[TRIALS] = {0};

	rng_init(&rng);
	rng_gen(&rng, klens, TRIALS);
	rng_gen(&rng, vlens, TRIALS);

	for (u64 i = 0; i < TRIALS; i++) {
		rng_gen(&rng, keys[i], MAX_KEY_LEN);
		rng_gen(&rng, values[i], MAX_VALUE_LEN);
		klens[i] %= (MAX_KEY_LEN / 2);
		klens[i] += (MAX_KEY_LEN / 2);
		vlens[i] %= (MAX_VALUE_LEN / 2);
		vlens[i] += (MAX_VALUE_LEN / 2);
		total_bytes += klens[i] + vlens[i] + sizeof(u32) + sizeof(u16);
	}

	for (u64 i = 0; i < TRIALS; i++) {
		LEAF_INSERT_AT(page, 512, 0, keys[i], klens[i], values[i],
			       vlens[i]);
	}

	ASSERT_EQ(PAGE_ELEMENTS(page), TRIALS, "elems");
	ASSERT_EQ(PAGE_TOTAL_BYTES(page), total_bytes, "total_bytes");

	for (u64 i = 0; i < TRIALS; i++) {
		u8 elem = TRIALS - i - 1;
		ASSERT_EQ(LEAF_KEY_LEN(page, elem), klens[i], "klen elem {}",
			  elem);
		ASSERT_EQ(LEAF_VALUE_LEN(page, elem), vlens[i], "vlen elem {}",
			  elem);

		ASSERT(!memcmp(LEAF_READ_KEY(page, elem), keys[i],
			       LEAF_KEY_LEN(page, elem)),
		       "key equal {}", elem);

		ASSERT(!memcmp(LEAF_READ_VALUE(page, elem), values[i],
			       LEAF_VALUE_LEN(page, elem)),
		       "value equal {}", elem);
	}

#undef TRIALS
#undef MAX_KEY_LEN
#undef MAX_VALUE_LEN
}

typedef struct {
	u8 _reserved[sizeof(RbTreeNode)];
	u8 key_len;
	u8 value_len;
	u8 key[32];
	u8 value[64];
} TestKeyValueNode;

i32 test_kv_search(RbTreeNode *cur, const RbTreeNode *value,
		   RbTreeNodePair *retval) {
	while (cur) {
		TestKeyValueNode *tkv_cur = (void *)cur;
		TestKeyValueNode *tkv_value = (void *)value;
		u16 min_len = min(tkv_cur->key_len, tkv_value->key_len);
		i32 cmp =
		    __builtin_memcmp(tkv_cur->key, tkv_value->key, min_len);

		// note that the min len is 16 so we know that the extra bytes
		// are not the tie breaker.
		if (!cmp) {
			retval->self = cur;
			break;
		} else if (cmp < 0) {
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

void visit_nodes(RbTreeNode *node, u8 keys[32][32], u8 values[32][64],
		 i32 *itt) {
	if (node->left) visit_nodes(node->left, keys, values, itt);
	TestKeyValueNode *value = (void *)node;
	__builtin_memcpy(keys[*itt], value->key, value->key_len);
	__builtin_memcpy(values[*itt], value->value, value->value_len);
	(*itt)++;
	if (node->right) visit_nodes(node->right, keys, values, itt);
}

Test(insert_ordered) {
#define TRIALS 32
#define MAX_KEY_LEN 32
#define MAX_VALUE_LEN 64
	u8 page[PAGE_SIZE] = {0};
	Rng rng;
	u64 total_bytes = 0;
	__attribute__((aligned(32))) u8 keys[TRIALS][MAX_KEY_LEN] = {0};
	__attribute__((aligned(32))) u8 values[TRIALS][MAX_VALUE_LEN] = {0};
	__attribute__((aligned(32))) u8 klens[TRIALS] = {0};
	__attribute__((aligned(32))) u8 vlens[TRIALS] = {0};
	RbTree tree = RBTREE_INIT;
	TestKeyValueNode nodes[TRIALS] = {0};

	rng_init(&rng);
	rng_gen(&rng, klens, TRIALS);
	rng_gen(&rng, vlens, TRIALS);

	for (u64 i = 0; i < TRIALS; i++) {
		rng_gen(&rng, keys[i], MAX_KEY_LEN);
		rng_gen(&rng, values[i], MAX_VALUE_LEN);
		for (u64 j = 0; j < MAX_KEY_LEN; j++)
			keys[i][j] = (keys[i][j] % 26) + 'A';
		for (u64 j = 0; j < MAX_VALUE_LEN; j++)
			values[i][j] = (values[i][j] % 26) + 'A';
		klens[i] %= (MAX_KEY_LEN / 2);
		klens[i] += (MAX_KEY_LEN / 2);
		vlens[i] %= (MAX_VALUE_LEN / 2);
		vlens[i] += (MAX_VALUE_LEN / 2);
		total_bytes += klens[i] + vlens[i] + sizeof(u32) + sizeof(u16);
		nodes[i].key_len = klens[i];
		nodes[i].value_len = vlens[i];
		__builtin_memcpy(nodes[i].key, keys[i], MAX_KEY_LEN);
		__builtin_memcpy(nodes[i].value, values[i], MAX_VALUE_LEN);
		rbtree_put(&tree, (RbTreeNode *)&nodes[i], test_kv_search);
	}

	for (u64 i = 0; i < TRIALS; i++) {
		LEAF_INSERT(page, 512, keys[i], klens[i], values[i], vlens[i]);
	}

	ASSERT_EQ(total_bytes, PAGE_TOTAL_BYTES(page), "total_bytes");

	i32 itt = 0;
	u8 rbkeys[32][32] = {0};
	u8 rbvalues[32][64] = {0};
	visit_nodes(tree.root, rbkeys, rbvalues, &itt);
	for (u64 i = 0; i < TRIALS; i++) {
		u8 pkey[65] = {0}, pvalue[65] = {0};
		u16 klen = LEAF_KEY_LEN(page, i);
		u16 vlen = LEAF_VALUE_LEN(page, i);
		__builtin_memcpy(pkey, LEAF_READ_KEY(page, i), klen);
		__builtin_memcpy(pvalue, LEAF_READ_VALUE(page, i), vlen);
		ASSERT(!strcmp(pkey, rbkeys[i]), "key equals");
		ASSERT(!strcmp(pvalue, rbvalues[i]), "value equals");
	}

#undef TRIALS
#undef MAX_KEY_LEN
#undef MAX_VALUE_LEN
}

Test(page_split) {
#define TRIALS 33
#define MAX_KEY_LEN 32
#define MAX_VALUE_LEN 64
	u8 page[PAGE_SIZE] = {0};
	u8 rpage[PAGE_SIZE] = {0};
	Rng rng;
	u64 total_bytes = 0;
	__attribute__((aligned(32))) u8 keys[TRIALS][MAX_KEY_LEN] = {0};
	__attribute__((aligned(32))) u8 values[TRIALS][MAX_VALUE_LEN] = {0};
	__attribute__((aligned(32))) u8 klens[TRIALS] = {0};
	__attribute__((aligned(32))) u8 vlens[TRIALS] = {0};
	u8 keys_read[TRIALS][MAX_KEY_LEN] = {0};
	u8 values_read[TRIALS][MAX_VALUE_LEN] = {0};
	u8 keys_compare[TRIALS][MAX_KEY_LEN] = {0};
	u8 values_compare[TRIALS][MAX_VALUE_LEN] = {0};

	rng_init(&rng);
	rng_gen(&rng, klens, TRIALS);
	rng_gen(&rng, vlens, TRIALS);

	for (u64 i = 0; i < TRIALS; i++) {
		rng_gen(&rng, keys[i], MAX_KEY_LEN);
		rng_gen(&rng, values[i], MAX_VALUE_LEN);
		klens[i] %= (MAX_KEY_LEN / 2);
		klens[i] += (MAX_KEY_LEN / 2);
		vlens[i] %= (MAX_VALUE_LEN / 2);
		vlens[i] += (MAX_VALUE_LEN / 2);
		total_bytes += klens[i] + vlens[i] + sizeof(u32) + sizeof(u16);
	}

	for (u64 i = 0; i < TRIALS; i++) {
		LEAF_INSERT_AT(page, 512, 0, keys[i], klens[i], values[i],
			       vlens[i]);
	}
	for (u64 i = 0; i < TRIALS; i++) {
		__builtin_memcpy(keys_read[i], LEAF_READ_KEY(page, i),
				 LEAF_KEY_LEN(page, i));
		__builtin_memcpy(values_read[i], LEAF_READ_VALUE(page, i),
				 LEAF_VALUE_LEN(page, i));
	}

	ASSERT_EQ(PAGE_ELEMENTS(page), TRIALS, "elements pre split");
	ASSERT_EQ(PAGE_TOTAL_BYTES(page), total_bytes, "bytes pre split");

	LEAF_SPLIT(page, 512, rpage);
	ASSERT_EQ(PAGE_ELEMENTS(page), TRIALS / 2, "elements left post split");
	ASSERT_EQ(PAGE_ELEMENTS(rpage), TRIALS / 2 + 1,
		  "elements right post split");
	ASSERT_EQ(total_bytes, PAGE_TOTAL_BYTES(page) + PAGE_TOTAL_BYTES(rpage),
		  "sum split");

	u64 i;
	for (i = 0; i < PAGE_ELEMENTS(page); i++) {
		__builtin_memcpy(keys_compare[i], LEAF_READ_KEY(page, i),
				 LEAF_KEY_LEN(page, i));
		__builtin_memcpy(values_compare[i], LEAF_READ_VALUE(page, i),
				 LEAF_VALUE_LEN(page, i));
	}
	for (u64 j = 0; j < PAGE_ELEMENTS(rpage); j++) {
		__builtin_memcpy(keys_compare[i], LEAF_READ_KEY(rpage, j),
				 LEAF_KEY_LEN(rpage, j));
		__builtin_memcpy(values_compare[i], LEAF_READ_VALUE(rpage, j),
				 LEAF_VALUE_LEN(rpage, j));
		i++;
	}

	for (i = 0; i < TRIALS; i++) {
		ASSERT(!strcmp(keys_read[i], keys_compare[i]), "key eq {}", i);
		ASSERT(!strcmp(values_read[i], values_compare[i]),
		       "value eq {}", i);
	}

#undef TRIALS
#undef MAX_KEY_LEN
#undef MAX_VALUE_LEN
}

Test(internal) {
	u8 page[PAGE_SIZE] = {0};
	INTERNAL_CREATE(page, 512, "mmm", 3, 3, 4);
	INTERNAL_INSERT(page, 512, "dddxyz", 6, 0, 5, 6);
	INTERNAL_INSERT(page, 512, "lox", 3, 1, 7, 8);
	INTERNAL_INSERT(page, 512, "xxxx", 4, 3, 9, 10);
	INTERNAL_INSERT(page, 512, "b123456789", 10, 0, 11, 12);
	INTERNAL_INSERT(page, 512, "abcd", 4, 0, 13, 14);
	INTERNAL_INSERT(page, 512, "y0000", 5, 6, 15, 16);
	u8 *key1 = "aaaaaaa", *key2 = "b0", *key3 = "b2av", *key4 = "lox",
	   *key5 = "ly", *key6 = "mzzz", *key7 = "xyz123", *key8 = "z";
	ASSERT_EQ(INTERNAL_FIND_PAGE(page, key1, strlen(key1)), 13, "key1");
	ASSERT_EQ(INTERNAL_FIND_PAGE(page, key2, strlen(key2)), 14, "key2");
	ASSERT_EQ(INTERNAL_FIND_PAGE(page, key3, strlen(key3)), 12, "key3");
	ASSERT_EQ(INTERNAL_FIND_PAGE(page, key4, strlen(key4)), 7, "key4");
	ASSERT_EQ(INTERNAL_FIND_PAGE(page, key5, strlen(key5)), 8, "key5");
	ASSERT_EQ(INTERNAL_FIND_PAGE(page, key6, strlen(key6)), 9, "key6");
	ASSERT_EQ(INTERNAL_FIND_PAGE(page, key7, strlen(key7)), 15, "key7");
	ASSERT_EQ(INTERNAL_FIND_PAGE(page, key8, strlen(key8)), 16, "key8");
}
