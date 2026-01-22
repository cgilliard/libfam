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
#include <libfam/famdb.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/lru.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif /* PAGE_SIZE */

struct FamDb {
	struct io_uring_params params;
	i32 ring_fd;
	u8 *sq_ring;
	u8 *cq_ring;
	struct io_uring_sqe *sqes;
	struct io_uring_cqe *cqes;
	u64 sq_ring_size;
	u64 cq_ring_size;
	u64 sqes_size;
	u32 *sq_tail;
	u32 *sq_array;
	u32 *cq_head;
	u32 *cq_tail;
	u32 *sq_mask;
	u32 *cq_mask;
	i32 fd;
	i32 fd_direct;
	u8 *file_data;
	u64 fmap_pages;
	u64 total_pages;
	u64 bitmap_bits;
	LruCache *cache;
	u8 *pages;
	u64 lru_capacity;
	u8 *free_page;
};

typedef struct {
	FamDb *db;
	FamDbScratch *scratch;
	u64 scratch_off;
	u64 root;
	u8 padding[256 - 32];
} FamDbTxnImpl;

typedef struct {
	u64 root;
} SuperBlock;

STATIC_ASSERT(sizeof(FamDbTxn) == sizeof(FamDbTxnImpl), fam_db_txn_size);

STATIC i32 famdb_init_db(FamDb *db) {
	println("init db root={}", db->fmap_pages);
	SuperBlock *sb = (void *)db->file_data;
	__astore64(&sb->root, db->fmap_pages);
	return 0;
}

i32 famdb_open(FamDb **dbret, const FamDbConfig *config) {
	FamDb *db;
	struct statx st = {0};

	if (!config->queue_depth || !config->pathname) {
		errno = EINVAL;
		return -1;
	}

	db = map(sizeof(FamDb));
	if (!db) return -1;

	db->cache = lru_init(config->lru_capacity, config->lru_hash_buckets);
	if (!db->cache) {
		famdb_close(db);
		return -1;
	}
	db->pages = map((config->lru_capacity + 1) * PAGE_SIZE);
	if (!db->pages) {
		famdb_close(db);
		return -1;
	}
	db->lru_capacity = config->lru_capacity;
	for (u64 i = 0; i < db->lru_capacity; i++)
		lru_put(db->cache, U64_MAX - i, db->pages + i * PAGE_SIZE);
	db->free_page = db->pages + db->lru_capacity * PAGE_SIZE;

	db->fd = open(config->pathname, O_RDWR | O_NOATIME | O_CLOEXEC, 0);
	if (db->fd < 0) {
		famdb_close(db);
		return -1;
	}
	db->fd_direct = open(config->pathname,
			     O_RDWR | O_DIRECT | O_NOATIME | O_CLOEXEC, 0);
	if (db->fd_direct < 0) {
		famdb_close(db);
		return -1;
	}

	if (fstatx(db->fd, &st) < 0) {
		famdb_close(db);
		return -1;
	}

	if (!st.stx_size || st.stx_size & (PAGE_SIZE - 1)) {
		errno = ENOTSUP;
		famdb_close(db);
		return -1;
	}

	u64 total_pages = st.stx_size / PAGE_SIZE;
	u64 total_bytes = (total_pages + 7) >> 3;
	u64 bitmap_pages = (total_bytes + (PAGE_SIZE - 1)) / PAGE_SIZE;
	db->fmap_pages = bitmap_pages + 1;
	db->total_pages = total_pages;

	if (total_pages <= db->fmap_pages) {
		errno = ENOTSUP;
		famdb_close(db);
		return -1;
	}

	db->bitmap_bits = total_pages - db->fmap_pages;

	db->file_data = fmap(db->fd, db->fmap_pages * PAGE_SIZE, 0);

	if (!db->file_data) {
		famdb_close(db);
		return -1;
	}

	db->params.flags = IORING_SETUP_SQPOLL;
	db->params.sq_thread_idle = 5;
	db->params.sq_thread_cpu = -1;

	db->ring_fd = io_uring_setup(config->queue_depth, &db->params);
	if (db->ring_fd < 0) {
		famdb_close(db);
		return -1;
	}

	db->sq_ring_size =
	    db->params.sq_off.array + db->params.sq_entries * sizeof(u32);
	db->cq_ring_size = db->params.cq_off.cqes +
			   db->params.cq_entries * sizeof(struct io_uring_cqe);
	db->sqes_size = db->params.sq_entries * sizeof(struct io_uring_sqe);

	db->sq_ring = mmap(NULL, db->sq_ring_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, db->ring_fd, IORING_OFF_SQ_RING);

	if (db->sq_ring == MAP_FAILED) {
		db->sq_ring = NULL;
		famdb_close(db);
		return -1;
	}

	db->cq_ring = mmap(NULL, db->cq_ring_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, db->ring_fd, IORING_OFF_CQ_RING);

	if (db->cq_ring == MAP_FAILED) {
		db->cq_ring = NULL;
		famdb_close(db);
		return -1;
	}
	db->sqes = mmap(NULL, db->sqes_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			db->ring_fd, IORING_OFF_SQES);
	if (db->sqes == MAP_FAILED) {
		db->sqes = NULL;
		famdb_close(db);
		return -1;
	}
	db->sq_tail = (u32 *)(db->sq_ring + db->params.sq_off.tail);
	db->sq_array = (u32 *)(db->sq_ring + db->params.sq_off.array);
	db->cq_head = (u32 *)(db->cq_ring + db->params.cq_off.head);
	db->cq_tail = (u32 *)(db->cq_ring + db->params.cq_off.tail);
	db->sq_mask = (u32 *)(db->sq_ring + db->params.sq_off.ring_mask);

	db->cq_mask = (u32 *)(db->cq_ring + db->params.cq_off.ring_mask);
	db->cqes =
	    (struct io_uring_cqe *)(db->cq_ring + db->params.cq_off.cqes);

	if (io_uring_register(db->ring_fd, IORING_REGISTER_FILES,
			      (i32[]){db->fd_direct}, 1) < 0) {
		famdb_close(db);
		return -1;
	}

	SuperBlock *sb = (void *)db->file_data;
	if (!sb->root) famdb_init_db(db);

	*dbret = db;
	return 0;
}

void famdb_close(FamDb *db) {
	if (!db) return;
	if (db->cache) lru_destroy(db->cache);
	db->cache = NULL;
	if (db->pages) munmap(db->pages, (db->lru_capacity + 1) * PAGE_SIZE);
	db->pages = NULL;
	if (db->fd > 0) close(db->fd);
	db->fd = -1;
	if (db->fd_direct > 0) close(db->fd_direct);
	db->fd_direct = -1;
	if (db->sq_ring) munmap(db->sq_ring, db->sq_ring_size);
	db->sq_ring = NULL;
	if (db->cq_ring) munmap(db->cq_ring, db->cq_ring_size);
	db->cq_ring = NULL;
	if (db->sqes) munmap(db->sqes, db->sqes_size);
	db->sqes = NULL;
	if (db->ring_fd > 0) raw_close(db->ring_fd);
	db->ring_fd = -1;
	if (db->file_data) munmap(db->file_data, db->fmap_pages * PAGE_SIZE);
	db->file_data = NULL;
	munmap(db, sizeof(FamDb));
}

i32 famdb_begin_txn(FamDbTxn *txn, FamDb *db, FamDbScratch *scratch) {
	FamDbTxnImpl *impl = (void *)txn;
	SuperBlock *sb;
	impl->scratch = scratch;
	impl->scratch_off = 0;
	impl->db = db;
	sb = (void *)impl->db->file_data;
	impl->root = __aload64(&sb->root);
	return 0;
}

i32 famdb_get(FamDbTxn *txn, const void *key, u64 key_len, void **value_out,
	      u64 *value_len_out) {
	return 0;
}

STATIC i32 famdb_get_page(FamDbTxnImpl *impl, u8 **page, u64 page_num) {
	u8 *page_from_cache = lru_get(impl->db->cache, page_num);

	if (page_from_cache) {
		*page = page_from_cache;
		return 0;
	}

	i32 result = 0;
	u32 index, cq_tail = 0, cq_head = 0;
	u32 flags = IORING_ENTER_SQ_WAKEUP;
	FamDb *db = impl->db;
	struct io_uring_sqe sqe = {.opcode = IORING_OP_READ,
				   .flags = IOSQE_FIXED_FILE,
				   .addr = (u64)impl->db->free_page,
				   .off = page_num * PAGE_SIZE,
				   .len = PAGE_SIZE,
				   .user_data = 1};

	index = *db->sq_tail & *db->sq_mask;
	db->sq_array[index] = index;
	db->sqes[index] = sqe;

	i32 res = io_uring_enter2(db->ring_fd, 0, 0, flags, NULL, 0);
	if (res < 0) return -1;
	__aadd32(db->sq_tail, 1);

	do {
		cq_tail = __aload32(db->cq_tail);
		cq_head = *db->cq_head;
		if (cq_tail != cq_head) {
			u32 idx = cq_head & *db->cq_mask;
			result = db->cqes[idx].res;

			if (result < 0 && cq_head != cq_tail) errno = -result;
			if (result != PAGE_SIZE) {
				errno = EIO;
				result = -1;
			}
			break;
		}
	} while (true);

	__aadd32(db->cq_head, 1);

	u8 *tail = lru_tail(impl->db->cache);
	lru_put(impl->db->cache, page_num, impl->db->free_page);
	*page = impl->db->free_page;
	impl->db->free_page = tail;

	return result;
}

i32 famdb_put(FamDbTxn *txn, const void *key, u64 key_len, const void *value,
	      u64 value_len) {
	FamDbTxnImpl *impl = (void *)txn;
	u8 *page = NULL;
	u8 buffer[PAGE_SIZE];

	if (famdb_get_page(impl, &page, impl->root) < 0) return -1;
	fastmemcpy(buffer, page, PAGE_SIZE);
	if (buffer[0]) println("buffer[0]={}", buffer[0]);
	if (famdb_get_page(impl, &page, impl->root + 1) < 0) return -1;
	fastmemcpy(buffer, page, PAGE_SIZE);
	if (buffer[0]) println("buffer[0]={}", buffer[0]);
	if (famdb_get_page(impl, &page, impl->root + 2) < 0) return -1;
	fastmemcpy(buffer, page, PAGE_SIZE);
	if (buffer[0]) println("buffer[0]={}", buffer[0]);

	return 0;
}

