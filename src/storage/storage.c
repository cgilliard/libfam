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

#include <libfam/format.h>
#include <libfam/iouring.h>
#include <libfam/linux.h>
#include <libfam/storage.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>

typedef struct CacheEntry {
	u8 page[PAGE_SIZE];
	struct CacheEntry *hash_next;
	struct CacheEntry *lru_next;
	struct CacheEntry *lru_prev;
	u64 sector;
	bool dirty;
	u8 padding[31];
} CacheEntry;

struct Storage {
	IoUring *iou;
	i32 fd;
	u64 cache_sector_count;
	CacheEntry **hash_buckets;
	u64 hash_bucket_count;
	CacheEntry *lru_head;
	CacheEntry *lru_tail;
	CacheEntry entries[];
};

Storage *storage_init(const u8 *path, u64 cache_sector_count,
		      u64 hash_bucket_count, u64 queue_size) {
	Storage *ret = NULL;
	IoUring *iou = NULL;
	i32 fd;

	fd = open(path, O_RDWR | O_DIRECT, 0);
	if (fd < 0) return NULL;

	if (iouring_init(&iou, queue_size) < 0) {
		close(fd);
		return NULL;
	}

	ret = map(sizeof(Storage) + cache_sector_count * sizeof(CacheEntry));
	if (!ret) {
		iouring_destroy(iou);
		close(fd);
		return NULL;
	}

	ret->hash_buckets = map(sizeof(CacheEntry *) * hash_bucket_count);
	if (!ret->hash_buckets) {
		munmap(ret, sizeof(Storage) +
				cache_sector_count * sizeof(CacheEntry));
		close(fd);
		iouring_destroy(iou);
		return NULL;
	}
	ret->lru_head = &ret->entries[0];
	ret->lru_tail = &ret->entries[cache_sector_count - 1];
	for (u64 i = 0; i < cache_sector_count; i++) {
		ret->entries[i].lru_next =
		    i < (cache_sector_count - 1) ? &ret->entries[i + 1] : NULL;
		ret->entries[i].lru_prev = i > 0 ? &ret->entries[i - 1] : NULL;
	}
	ret->hash_bucket_count = hash_bucket_count;
	ret->cache_sector_count = cache_sector_count;
	ret->fd = fd;
	ret->iou = iou;

	return ret;
}

i32 storage_write(Storage *s, const u8 buffer[PAGE_SIZE], u64 sector) {
	return 0;
}

i32 storage_read(Storage *s, u8 buffer[PAGE_SIZE], u64 sector) {
	// u64 id;
	iouring_init_pread(s->iou, s->fd, buffer, PAGE_SIZE, sector * PAGE_SIZE,
			   1);
	iouring_submit(s->iou, 1);

	return 0;
}

i32 storage_flush(Storage *s) { return 0; }
void storage_destroy(Storage *s) {
	if (s) {
		if (s->iou) iouring_destroy(s->iou);
		s->iou = NULL;
		if (s->fd >= 0) close(s->fd);
		s->fd = -1;
		if (s->hash_buckets)
			munmap(s->hash_buckets,
			       sizeof(CacheEntry *) * s->hash_bucket_count);
		s->hash_buckets = NULL;
		munmap(s, sizeof(Storage) +
			      s->cache_sector_count * sizeof(CacheEntry));
	}
}

