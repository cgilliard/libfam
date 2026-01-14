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

#include <libfam/atomic.h>
#include <libfam/format.h>
#include <libfam/iouring.h>
#include <libfam/linux.h>
#include <libfam/storage.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>

typedef struct CacheEntry {
	u8 *page;
	struct CacheEntry *hash_next;
	struct CacheEntry *lru_next;
	struct CacheEntry *lru_prev;
	u64 sector;
	bool dirty;
} CacheEntry;

struct Storage {
	IoUring *readiou;
	IoUring *writeiou;
	i32 fd;
	u64 cache_sector_count;
	CacheEntry **hash_buckets;
	u64 hash_bucket_count;
	u8 *pages;
	CacheEntry *lru_head;
	CacheEntry *lru_tail;
	CacheEntry entries[];
};

Storage *storage_init(const u8 *path, u64 cache_sector_count,
		      u64 hash_bucket_count, u64 queue_size) {
	Storage *s =
	    map(sizeof(Storage) + sizeof(CacheEntry) * cache_sector_count);
	if (!s) return NULL;
	s->cache_sector_count = cache_sector_count;
	if (iouring_init(&s->readiou, 1) < 0) {
		storage_destroy(s);
		return NULL;
	}
	if (iouring_init(&s->writeiou, queue_size) < 0) {
		storage_destroy(s);
		return NULL;
	}
	s->fd = open(path, O_RDWR | O_DIRECT, 0);
	if (io_uring_register(iouring_ring_fd(s->readiou),
			      IORING_REGISTER_FILES, (i32[]){s->fd}, 1) < 0) {
		storage_destroy(s);
		return NULL;
	}
	if (io_uring_register(iouring_ring_fd(s->writeiou),
			      IORING_REGISTER_FILES, (i32[]){s->fd}, 1) < 0) {
		storage_destroy(s);
		return NULL;
	}
	s->pages = map(cache_sector_count * PAGE_SIZE);
	if (!s->pages) {
		storage_destroy(s);
		return NULL;
	}
	for (u64 i = 0; i < cache_sector_count; i++) {
	}
	return s;
}

i32 storage_write(Storage *s, const u8 buffer[PAGE_SIZE], u64 sector) {
	return 0;
}

i32 storage_read(Storage *s, u64 sector, u64 id,
		 const StorageReadOnComplete *callback) {
	return 0;
}
i32 storage_flush(Storage *s, u64 id, const StorageFlushOnComplete *callback) {
	return 0;
}

void storage_destroy(Storage *s) {
	if (s) {
		if (s->readiou) iouring_destroy(s->readiou);
		s->readiou = NULL;
		if (s->writeiou) iouring_destroy(s->writeiou);
		s->writeiou = NULL;
		if (s->fd > 0) close(s->fd);
		if (s->pages)
			munmap(s->pages, s->cache_sector_count * PAGE_SIZE);
		munmap(s, sizeof(Storage) +
			      sizeof(CacheEntry) * s->cache_sector_count);
	}
}

