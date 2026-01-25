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
#include <libfam/hashtable.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/lru.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif /* PAGE_SIZE */

struct FamDb {
	FamDbConfig config;
	i32 ring_fd;
	struct io_uring_params params;
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
	u8 *map;
	u64 fmap_pages;
	u64 total_pages;
	u64 bitmap_bits;
	LruCache *cache;
	u8 *pages;
	u8 *free_page;
	u64 last_free;
};

typedef struct {
	u64 root;
	u64 seqno;
} Commit;

typedef union {
	u128 value;
	Commit commit;
} CommitUnion;

typedef struct {
	CommitUnion commit;
} SuperBlock;

typedef struct {
	CommitUnion commit;
	FamDb *db;
	FamDbScratch *scratch;
	u64 scratch_off;
	u64 root;
	u64 seqno;
	Hashtable *hashtable;
	u8 padding[256 - 64];
} FamDbTxnImpl;

typedef struct {
	u8 _reserved[HASHTABLE_KEY_VALUE_OVERHEAD];
	u64 key;
	u8 page[PAGE_SIZE];
	u64 replaced_pageno;
} HashtableEntry;

STATIC_ASSERT(sizeof(FamDbTxn) == sizeof(FamDbTxnImpl), fam_db_txn_size);

#define PAGE_TYPE_INTERNAL_FLAG (0x1 << 0)

#define FIRST_OFFSET 512
#define PAGE_IS_INTERNAL(page) ((page[0] & PAGE_TYPE_INTERNAL_FLAG))
#define PAGE_IS_LEAF(page) (!(page[0] & PAGE_TYPE_INTERNAL_FLAG))
#define PAGE_ELEMENTS(page) (((u16 *)page)[1])
#define PAGE_TOTAL_BYTES(page) (((u16 *)page)[2])
#define PAGE_READ_KEY_LEN(page, elem) \
	(((u16 *)(page + PAGE_OFFSET_OF(page, elem) + sizeof(u32)))[0])
#define PAGE_READ_VALUE(page, elem)                                      \
	(page + PAGE_OFFSET_OF(page, elem) + sizeof(u32) + sizeof(u16) + \
	 PAGE_READ_KEY_LEN(page, elem))
#define PAGE_OFFSET_OF(page, elem) (((u16 *)page)[elem + 3])
#define PAGE_KV_LEN(page, elem) \
	(((u32 *)(page + PAGE_OFFSET_OF(page, elem)))[0])
#define PAGE_COMPARE_KEYS(page, key, key_len, elem)                       \
	({                                                                \
		u16 elem_key_off = PAGE_OFFSET_OF(page, elem);            \
		u16 elem_key_len = PAGE_READ_KEY_LEN(page, elem);         \
		u16 min_len = min(key_len, elem_key_len);                 \
		i32 cmp = fastmemcmp(                                     \
		    key, page + elem_key_off + sizeof(u32) + sizeof(u16), \
		    min_len);                                             \
		cmp != 0		 ? cmp                            \
		: key_len > elem_key_len ? 1                              \
		: key_len < elem_key_len ? -1                             \
					 : 0;                             \
	})
#define PAGE_FIND_INDEX(page, key, key_len)                               \
	({                                                                \
		u16 min = 0, max = PAGE_ELEMENTS(page), mid;              \
		i32 cmp;                                                  \
		while (min < max) {                                       \
			mid = min + ((max - min) >> 1);                   \
			cmp = PAGE_COMPARE_KEYS(page, key, key_len, mid); \
			if (cmp == 0) {                                   \
				min = mid;                                \
				break;                                    \
			} else if (cmp < 0)                               \
				max = mid;                                \
			else                                              \
				min = mid + 1;                            \
		}                                                         \
		min;                                                      \
	})
#define PAGE_INSERT_BEFORE(page, elem, key, key_len, value, value_len)        \
	({                                                                    \
		u16 _offset__ = PAGE_OFFSET_OF(page, elem);                   \
		if (_offset__ == 0) {                                         \
			_offset__ = PAGE_TOTAL_BYTES(page) + FIRST_OFFSET;    \
			((u16 *)page)[elem + 3] = _offset__;                  \
		}                                                             \
		u16 _nentry_len__ =                                           \
		    key_len + value_len + sizeof(u16) + sizeof(u32);          \
		if (PAGE_ELEMENTS(page) > elem)                               \
			fastmemmove(page + _offset__ + _nentry_len__,         \
				    page + _offset__,                         \
				    FIRST_OFFSET + PAGE_TOTAL_BYTES(page) -   \
					_offset__);                           \
		((u16 *)page)[2] += _nentry_len__;                            \
		((u16 *)page)[1]++;                                           \
		((u32 *)(page + _offset__))[0] = key_len + value_len;         \
		((u16 *)(page + _offset__ + sizeof(u32)))[0] = key_len;       \
		fastmemcpy(page + _offset__ + sizeof(u32) + sizeof(u16), key, \
			   key_len);                                          \
		fastmemcpy(                                                   \
		    page + _offset__ + sizeof(u32) + sizeof(u16) + key_len,   \
		    value, value_len);                                        \
		for (u32 i = elem + 1; i < PAGE_ELEMENTS(page); i++)          \
			((u16 *)page)[i + 3] = ((u16 *)page)[i + 2] +         \
					       PAGE_KV_LEN(page, i - 1) +     \
					       sizeof(u16) + sizeof(u32);     \
	})
#define GET_PAGE(impl, page_ptr, pageno, key, key_len)                       \
	({                                                                   \
		*(page_ptr) = hashtable_get(impl->hashtable, *pageno);       \
		if (!*(page_ptr)) {                                          \
			if (famdb_get_page(impl, &(*page_ptr), *pageno) < 0) \
				return -1;                                   \
		}                                                            \
	})
#define NEXT_PAGE(impl, page_ptr, pageno, key, key_len)                      \
	({                                                                   \
		*(page_ptr) = hashtable_get(impl->hashtable, *pageno);       \
		if (!*(page_ptr)) {                                          \
			if (famdb_get_page(impl, &(*page_ptr), *pageno) < 0) \
				return -1;                                   \
			HashtableEntry *nent =                               \
			    ALLOC(impl, sizeof(HashtableEntry));             \
			if (!nent) return -1;                                \
			nent->replaced_pageno = *pageno;                     \
			i64 npage = BITMAP_ALLOC_PAGE(impl->db);             \
			if (npage < 0) return -1;                            \
			nent->key = npage;                                   \
			hashtable_put(impl->hashtable, (void *)nent);        \
			fastmemcpy(nent->page, *(page_ptr), PAGE_SIZE);      \
			*(page_ptr) = nent->page;                            \
			if (*pageno == impl->root) impl->root = nent->key;   \
			*pageno = nent->key;                                 \
			/* TODO: must update parent pointer if               \
				      it points to old page */               \
		}                                                            \
	})
#define BITMAP_ALLOC_PAGE(db)                                            \
	({                                                               \
		i64 ret = -1;                                            \
		u64 bit = 0, lw_offset, initial_offset = db->last_free;  \
		while (true) {                                           \
			lw_offset = db->last_free;                       \
			u64 *map_ptr = (u64 *)(db->map + PAGE_SIZE +     \
					       lw_offset * sizeof(u64)); \
			u64 cur = __aload64(map_ptr);                    \
			if (cur == U64_MAX) {                            \
				db->last_free = (db->last_free + 1) %    \
						(db->bitmap_bits >> 6);  \
				if (db->last_free == initial_offset) {   \
					errno = ENOMEM;                  \
					break;                           \
				}                                        \
			} else {                                         \
				bit = __builtin_ctzll(~cur);             \
				u64 new = cur | (1UL << bit);            \
				if (__cas64(map_ptr, &cur, new)) {       \
					ret = bit + (lw_offset << 6) +   \
					      db->fmap_pages;            \
					break;                           \
				}                                        \
			}                                                \
		}                                                        \
		ret;                                                     \
	})
#define BITMAP_RELEASE_PAGE(db, pageno)                                       \
	({                                                                    \
		if (pageno < db->fmap_pages) panic("Invalid page released!"); \
		u64 bit_offset = pageno - db->fmap_pages;                     \
		u64 cur;                                                      \
		u64 bit_to_zero = (1ULL << (bit_offset & 0x3F));              \
		u64 lw_offset = bit_offset >> 6;                              \
		u64 *map_ptr =                                                \
		    (u64 *)(db->map + PAGE_SIZE + lw_offset * sizeof(u64));   \
		do {                                                          \
			cur = __aload64(map_ptr);                             \
			if (!(cur & bit_to_zero))                             \
				panic("double free {}", pageno);              \
		} while (!__cas64(map_ptr, &cur, cur & ~bit_to_zero));        \
		db->last_free = lw_offset;                                    \
	})
#define ALLOC(impl, size)                                                  \
	({                                                                 \
		void *_ret__;                                              \
		if (size + impl->scratch_off > impl->scratch->capacity) {  \
			errno = ENOMEM;                                    \
			_ret__ = NULL;                                     \
		} else {                                                   \
			_ret__ = impl->scratch->space + impl->scratch_off; \
			impl->scratch_off += size;                         \
		}                                                          \
		_ret__;                                                    \
	})

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
				println("result={},ps={}", result, PAGE_SIZE);
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

STATIC i32 famdb_init_db(FamDb *db) {
	if (BITMAP_ALLOC_PAGE(db) != db->fmap_pages) {
		errno = EINVAL;
		return -1;
	}
	SuperBlock *sb = (void *)db->map;
	u128 expected = 0;
	CommitUnion cu = {.commit.root = db->fmap_pages};
	return !__cas128(&sb->commit.value, &expected, cu.value);
}

i32 famdb_open(FamDb **dbret, const FamDbConfig *config) {
	FamDb *db;
	struct statx st = {0};
	i32 fd;

	if (!config->queue_depth || !config->pathname) {
		errno = EINVAL;
		return -1;
	}

	db = map(sizeof(FamDb));
	if (!db) return -1;

	db->config = *config;
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
	for (u64 i = 0; i < db->config.lru_capacity; i++)
		lru_put(db->cache, U64_MAX - i, db->pages + i * PAGE_SIZE);
	db->free_page = db->pages + db->config.lru_capacity * PAGE_SIZE;

	fd = open(config->pathname, O_RDWR | O_NOATIME | O_CLOEXEC, 0);

	if (fd < 0) {
		famdb_close(db);
		return -1;
	}

	if (fstatx(fd, &st) < 0) {
		close(fd);
		famdb_close(db);
		return -1;
	}

	u64 total_pages = st.stx_size / PAGE_SIZE;
	u64 total_bytes = (total_pages + 7) >> 3;
	u64 bitmap_pages = (total_bytes + (PAGE_SIZE - 1)) / PAGE_SIZE;
	db->fmap_pages = bitmap_pages + 1;
	db->total_pages = total_pages;

	if (total_pages <= db->fmap_pages) {
		close(fd);
		errno = ENOTSUP;
		famdb_close(db);
		return -1;
	}

	db->bitmap_bits = (total_pages - db->fmap_pages) & ~63ULL;
	db->map = fmap(fd, db->fmap_pages * PAGE_SIZE, 0);
	close(fd);
	if (!db->map) {
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

	db->fd = open(config->pathname,
		      O_RDWR | O_DIRECT | O_NOATIME | O_CLOEXEC, 0);
	if (db->fd < 0) {
		famdb_close(db);
		return -1;
	}

	if (io_uring_register(db->ring_fd, IORING_REGISTER_FILES,
			      (i32[]){db->fd}, 1) < 0) {
		famdb_close(db);
		return -1;
	}

	SuperBlock *sb = (void *)db->map;
	if (!sb->commit.value) {
		if (famdb_init_db(db) < 0) {
			famdb_close(db);
			return -1;
		}
	}

	*dbret = db;

	return 0;
}

void famdb_close(FamDb *db) {
	if (!db) return;
	if (db->cache) lru_destroy(db->cache);
	db->cache = NULL;
	if (db->pages)
		munmap(db->pages, (db->config.lru_capacity + 1) * PAGE_SIZE);
	db->pages = NULL;
	if (db->fd > 0) close(db->fd);
	db->fd = -1;
	if (db->sq_ring) munmap(db->sq_ring, db->sq_ring_size);
	db->sq_ring = NULL;
	if (db->cq_ring) munmap(db->cq_ring, db->cq_ring_size);
	db->cq_ring = NULL;
	if (db->sqes) munmap(db->sqes, db->sqes_size);
	db->sqes = NULL;
	if (db->ring_fd > 0) raw_close(db->ring_fd);
	db->ring_fd = -1;
	if (db->map) munmap(db->map, db->fmap_pages * PAGE_SIZE);
	db->map = NULL;
	munmap(db, sizeof(FamDb));
}

i32 famdb_create_scratch(FamDbScratch *scratch, u64 size) {
	scratch->space = map(size);
	if (!scratch->space) return -1;
	scratch->capacity = size;
	return 0;
}
void famdb_destroy_scratch(FamDbScratch *scratch) {
	munmap(scratch->space, scratch->capacity);
}

void famdb_txn_begin(FamDbTxn *txn, FamDb *db, FamDbScratch *scratch) {
	FamDbTxnImpl *impl = (void *)txn;
	impl->db = db;
	SuperBlock *sb = (void *)impl->db->map;
	impl->scratch = scratch;
	fastmemset(scratch->space, 0, scratch->capacity);

	impl->scratch_off = sizeof(void *) * db->config.scratch_hash_buckets +
			    sizeof(Hashtable);
	impl->hashtable = (void *)impl->scratch->space;
	hashtable_init(impl->hashtable, db->config.scratch_hash_buckets,
		       (void *)(impl->scratch->space + sizeof(Hashtable)));
	impl->commit.value = __aload128(&sb->commit.value);
	impl->root = impl->commit.commit.root;
}

i32 famdb_get(FamDbTxn *txn, const void *key, u64 key_len, void *value_out,
	      u64 value_out_capacity, u64 offset) {
	FamDbTxnImpl *impl = (void *)txn;
	u64 *pageno = &impl->root;
	u8 *page = NULL;

	do GET_PAGE(impl, &page, pageno, key, key_len);
	while (PAGE_IS_INTERNAL(page));
	perror("getpage");

	// println("elems={},pageno={}", PAGE_ELEMENTS(page), (u64)*pageno);
	perror("z");

	u64 nindex = PAGE_FIND_INDEX(page, key, key_len);
	perror("y");
	i32 cmp = PAGE_COMPARE_KEYS(page, key, key_len, nindex);
	perror("x");
	if (cmp) {
		errno = ENOENT;
		return -1;
	}
	// println("found!");
	perror("pre memcpy");
	u64 value_len =
	    PAGE_KV_LEN(page, nindex) - PAGE_READ_KEY_LEN(page, nindex);
	u64 min_len = min(value_out_capacity, value_len);
	fastmemcpy(value_out, PAGE_READ_VALUE(page, nindex), min_len);

	return min_len;
}

i32 famdb_set(FamDbTxn *txn, const void *key, u64 key_len, const void *value,
	      u64 value_len, u64 offset) {
	i32 ret = 0;
	FamDbTxnImpl *impl = (void *)txn;
	u64 *pageno = &impl->root;
	u8 *page = NULL;

	do NEXT_PAGE(impl, &page, pageno, key, key_len);
	while (PAGE_IS_INTERNAL(page));

	u64 index = PAGE_FIND_INDEX(page, key, key_len);
	PAGE_INSERT_BEFORE(page, index, key, key_len, value, value_len);

	return ret;
}

i32 famdb_txn_commit(FamDbTxn *txn) {
	FamDbTxnImpl *impl = (void *)txn;
	FamDb *db = impl->db;
	i32 result;
	u32 flags = IORING_ENTER_SQ_WAKEUP, index, cq_head, cq_tail;
	u64 size = sizeof(HashtableEntry);
	u64 count = 0;

	i32 res = io_uring_enter2(db->ring_fd, 0, 0, flags, NULL, 0);
	if (res < 0) return -1;

	for (u64 i = impl->scratch_off;
	     i > sizeof(void *) * impl->db->config.scratch_hash_buckets +
		     sizeof(Hashtable);
	     i -= size) {
		u64 *npagenum = (void *)(impl->scratch->space + i -
					 (PAGE_SIZE + sizeof(u64) * 2));
		u8 *page = (void *)(impl->scratch->space + i -
				    (PAGE_SIZE + sizeof(u64)));

		struct io_uring_sqe write_sqe = {.opcode = IORING_OP_WRITE,
						 .flags = IOSQE_FIXED_FILE,
						 .addr = (u64)page,
						 .off = (*npagenum) * PAGE_SIZE,
						 .len = PAGE_SIZE,
						 .user_data = ++count};

		index = *db->sq_tail & *db->sq_mask;
		db->sq_array[index] = index;
		db->sqes[index] = write_sqe;
		__aadd32(db->sq_tail, 1);
	}

	for (u64 i = 0; i < count; i++) {
		do {
			cq_tail = __aload32(db->cq_tail);
			cq_head = *db->cq_head;
			if (cq_tail != cq_head) {
				u32 idx = cq_head & *db->cq_mask;
				result = db->cqes[idx].res;

				if (result < 0 && cq_head != cq_tail)
					errno = -result;
				if (result != PAGE_SIZE) {
					println("result={},ps={}", result,
						PAGE_SIZE);
					errno = EIO;
					result = -1;
				}
				break;
			}
		} while (true);

		__aadd32(db->cq_head, 1);
	}

	struct io_uring_sqe sync_sqe = {.opcode = IORING_OP_FSYNC,
					.fd = db->fd,
					.fsync_flags = IORING_FSYNC_DATASYNC,
					.user_data = U64_MAX};
	index = *db->sq_tail & *db->sq_mask;
	db->sq_array[index] = index;
	db->sqes[index] = sync_sqe;
	__aadd32(db->sq_tail, 1);

	do {
		cq_tail = __aload32(db->cq_tail);
		cq_head = *db->cq_head;
		if (cq_tail != cq_head) {
			u32 idx = cq_head & *db->cq_mask;
			result = db->cqes[idx].res;

			if (result < 0 && cq_head != cq_tail) errno = -result;
			if (result < 0) {
				errno = -result;
				result = -1;
			}
			break;
		}
	} while (true);

	if (result < 0) return -1;

	__aadd32(db->cq_head, 1);
	CommitUnion commit = {.commit.seqno = impl->commit.commit.seqno + 1,
			      .commit.root = impl->root};

	SuperBlock *sb = (void *)db->map;
	CommitUnion expected = impl->commit;
	result = !__cas128(&sb->commit.value, &expected.value, commit.value);
	return result;
}
