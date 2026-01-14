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
#include <libfam/lru.h>
#include <libfam/rng.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>

typedef struct LruCacheEntry {
	struct LruCacheEntry *hash_next;
	struct LruCacheEntry *lru_next;
	struct LruCacheEntry *lru_prev;
	u64 bucket;
	u64 key;
	u8 value[];
} LruCacheEntry;

struct LruCache {
	LruCacheEntry *entries;
	u64 capacity;
	u64 value_size;
	u64 hash_bucket_count;
	LruCacheEntry **hash_buckets;
	LruCacheEntry *lru_head;
	LruCacheEntry *lru_tail;
	u64 seed;
};

LruCache *lru_init(u64 capacity, u64 hash_bucket_count, u64 value_size) {
	Rng rng;
	LruCache *cache;

	if (capacity == 0 || hash_bucket_count == 0 || value_size == 0) {
		errno = EINVAL;
		return NULL;
	}

	cache = map(sizeof(LruCache));
	if (!cache) return NULL;
	cache->capacity = capacity;
	cache->value_size = value_size;
	cache->hash_bucket_count = hash_bucket_count;

	cache->entries =
	    map((sizeof(LruCacheEntry) + cache->value_size) * cache->capacity);
	if (!cache->entries) {
		lru_destroy(cache);
		return NULL;
	}
	cache->hash_buckets =
	    map(sizeof(LruCacheEntry *) * cache->hash_bucket_count);

	for (u64 i = 0; i < capacity; i++) {
		LruCacheEntry *ent =
		    (void *)((u8 *)cache->entries +
			     i * (sizeof(LruCacheEntry) + cache->value_size));
		ent->lru_prev =
		    i == 0 ? NULL
			   : (void *)((u8 *)cache->entries +
				      (i - 1) * (sizeof(LruCacheEntry) +
						 cache->value_size));
		ent->lru_next =
		    i == capacity - 1
			? NULL
			: (void *)((u8 *)cache->entries +
				   (i + 1) * (sizeof(LruCacheEntry) +
					      cache->value_size));
	}
	cache->lru_head = &cache->entries[0];
	cache->lru_tail = (void *)((u8 *)cache->entries +
				   (capacity - 1) * (sizeof(LruCacheEntry) +
						     cache->value_size));
	rng_init(&rng);
	rng_gen(&rng, &cache->seed, sizeof(u64));

	return cache;
}
void lru_destroy(LruCache *cache) {
	if (cache) {
		if (cache->entries)
			munmap(cache->entries,
			       (sizeof(LruCacheEntry) + cache->value_size) *
				   cache->capacity);
		if (cache->hash_buckets)
			munmap(
			    cache->hash_buckets,
			    sizeof(LruCacheEntry *) * cache->hash_bucket_count);
		munmap(cache, sizeof(LruCache));
	}
}
void *lru_get(LruCache *cache, u64 key) {
	u64 bucket = aighthash64(&key, sizeof(u64), cache->seed) %
		     cache->hash_bucket_count;

	LruCacheEntry *ent = cache->hash_buckets[bucket];
	while (ent) {
		if (ent->key == key) {
			if (ent != cache->lru_head) {
				if (ent->lru_prev)
					ent->lru_prev->lru_next = ent->lru_next;
				if (ent->lru_next)
					ent->lru_next->lru_prev = ent->lru_prev;
				if (ent == cache->lru_tail)
					cache->lru_tail = ent->lru_prev;
				LruCacheEntry *old_head = cache->lru_head;
				cache->lru_head = ent;
				ent->lru_next = old_head;
				ent->lru_prev = NULL;
				old_head->lru_prev = ent;
			}
			return ent->value;
		}
		ent = ent->hash_next;
	}
	return NULL;
}

void lru_put(LruCache *cache, u64 key, void *value) {
	u64 bucket = aighthash64(&key, sizeof(u64), cache->seed) %
		     cache->hash_bucket_count;
	LruCacheEntry *nent = cache->lru_tail;
	u64 old_bucket = nent->bucket;
	LruCacheEntry **head = &cache->hash_buckets[old_bucket];
	while (*head) {
		if (*head == nent) {
			*head = nent->hash_next;
			break;
		}
		head = &(*head)->hash_next;
	}

	nent->bucket = bucket;
	nent->key = key;
	fastmemcpy(nent->value, value, cache->value_size);
	cache->lru_tail = nent->lru_prev;
	nent->lru_next = cache->lru_head;
	nent->lru_prev = NULL;
	cache->lru_head->lru_prev = nent;
	cache->lru_head = nent;
	cache->lru_tail->lru_next = NULL;
	nent->hash_next = cache->hash_buckets[bucket];
	cache->hash_buckets[bucket] = nent;
}

void *lru_tail(LruCache *cache) { return cache->lru_tail; }
