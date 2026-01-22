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

#include <libfam/aighthash.h>
#include <libfam/format.h>
#include <libfam/hashtable.h>
#include <libfam/rng.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>
#include <libfam/utils.h>

typedef struct HashtableEntry {
	struct HashtableEntry *hash_next;
	u8 data[];
} HashtableEntry;

STATIC_ASSERT(sizeof(HashtableEntry) == HASHTABLE_KEY_VALUE_OVERHEAD,
	      hashtable_overhead);

typedef struct {
	u64 key_size;
	u64 value_size;
	u64 hash_bucket_count;
	HashtableEntry **hash_buckets;
	u64 seed;
} HashtableImpl;

void hashtable_init(Hashtable *h, u64 hash_bucket_count, u64 key_size,
		    u64 value_size, void **hash_buckets) {
	HashtableImpl *impl = (void *)h;
	Rng rng;

	rng_init(&rng);

	impl->hash_bucket_count = hash_bucket_count;
	impl->key_size = key_size;
	impl->value_size = value_size;
	rng_gen(&rng, &impl->seed, sizeof(u64));
	impl->hash_buckets = (void *)hash_buckets;
}

void *hashtable_get(Hashtable *h, const void *key) {
	HashtableImpl *hashtable = (void *)h;
	u64 bucket = aighthash64(key, hashtable->key_size, hashtable->seed) %
		     hashtable->hash_bucket_count;
	HashtableEntry *ent = hashtable->hash_buckets[bucket];
	while (ent) {
		if (!fastmemcmp(ent->data, key, hashtable->key_size))
			return (void *)((u8 *)ent->data + hashtable->key_size);
		ent = ent->hash_next;
	}
	return NULL;
}
void hashtable_put(Hashtable *h, const HashtableKeyValue *kv) {
	HashtableImpl *hashtable = (void *)h;
	u64 bucket =
	    aighthash64(kv->data, hashtable->key_size, hashtable->seed) %
	    hashtable->hash_bucket_count;
	((HashtableEntry *)kv)->hash_next = hashtable->hash_buckets[bucket];
	hashtable->hash_buckets[bucket] = (HashtableEntry *)kv;
}
HashtableKeyValue *hashtable_remove(Hashtable *h, const void *key) {
	HashtableImpl *hashtable = (void *)h;
	u64 bucket = aighthash64(key, hashtable->key_size, hashtable->seed) %
		     hashtable->hash_bucket_count;
	HashtableEntry **head = &hashtable->hash_buckets[bucket];
	while (*head) {
		if (!fastmemcmp((*head)->data, key, hashtable->key_size)) {
			void *ret = *head;
			*head = (*head)->hash_next;
			return ret;
		}
		head = &(*head)->hash_next;
	}
	return NULL;
}

