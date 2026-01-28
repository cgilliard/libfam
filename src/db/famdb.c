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

#include <libfam/famdb.h>
#include <libfam/famdb_ops.h>
#include <libfam/fstatx.h>
#include <libfam/hashtable.h>
#include <libfam/iouring.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/lru.h>
#include <libfam/syscall.h>
#include <libfam/sysext.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif /* PAGE_SIZE */

#define MAX_LEVELS 256

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
	Hashtable *hashtable;
	u8 padding[256 - 64];
} FamDbTxnImpl;

typedef struct {
	u8 page[PAGE_SIZE];
	u64 disk_pageno;
} HashtableEntryValue;

typedef struct {
	u8 _reserved[HASHTABLE_KEY_VALUE_OVERHEAD];
	u64 key;
	HashtableEntryValue value;
} HashtableEntry;

typedef struct {
	u16 index;
	u64 pageno;
	u8 *page;
	bool is_in_scratch;
} LevelInfo;

typedef struct {
	u16 levels;
	LevelInfo info[MAX_LEVELS];
} FamDbState;

STATIC_ASSERT(sizeof(FamDbTxn) == sizeof(FamDbTxnImpl), fam_db_txn_size);

#define PAGE_RESV 16
#define MAX_ELEMENTS(data_off) (((data_off - sizeof(u64)) >> 1) - 3)
#define AVAILABLE(data_off) (PAGE_SIZE - (data_off + PAGE_RESV))
#define BITMAP_ALLOC_PAGE(db)                                                  \
	({                                                                     \
		i64 ret = -1;                                                  \
		u64 bit = 0, lw_offset, initial_offset = db->last_free;        \
		while (true) {                                                 \
			lw_offset = db->last_free;                             \
			u64 *map_ptr = (u64 *)(db->map + PAGE_SIZE +           \
					       lw_offset * sizeof(u64));       \
			u64 cur = __atomic_load_n(map_ptr, __ATOMIC_SEQ_CST);  \
			if (cur == U64_MAX) {                                  \
				db->last_free = (db->last_free + 1) %          \
						(db->bitmap_bits >> 6);        \
				if (db->last_free == initial_offset) {         \
					errno = ENOMEM;                        \
					break;                                 \
				}                                              \
			} else {                                               \
				bit = __builtin_ctzll(~cur);                   \
				u64 nblock = cur | (1UL << bit);               \
				if (__atomic_compare_exchange(                 \
					map_ptr, &cur, &nblock, false,         \
					__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) { \
					ret = bit + (lw_offset << 6) +         \
					      db->fmap_pages;                  \
					break;                                 \
				}                                              \
			}                                                      \
		}                                                              \
		ret;                                                           \
	})
#define BITMAP_RELEASE_PAGE(db, pageno)                                      \
	({                                                                   \
		if (pageno < db->fmap_pages)                                 \
			panic(                                               \
			    "Invali"                                         \
			    "d "                                             \
			    "page "                                          \
			    "releas"                                         \
			    "ed!");                                          \
		u64 bit_offset = pageno - db->fmap_pages;                    \
		u64 cur, desired;                                            \
		u64 bit_to_zero = (1ULL << (bit_offset & 0x3F));             \
		u64 lw_offset = bit_offset >> 6;                             \
		u64 *map_ptr =                                               \
		    (u64 *)(db->map + PAGE_SIZE + lw_offset * sizeof(u64));  \
		do {                                                         \
			cur = __atomic_load_n(map_ptr, __ATOMIC_SEQ_CST);    \
			if (!(cur & bit_to_zero))                            \
				panic("double free {}", pageno);             \
			desired = cur & ~bit_to_zero;                        \
		} while (!__atomic_compare_exchange(map_ptr, &cur, &desired, \
						    false, __ATOMIC_SEQ_CST, \
						    __ATOMIC_SEQ_CST));      \
		db->last_free = lw_offset;                                   \
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
#define GET_PAGE(impl, state, key, key_len)                                   \
	({                                                                    \
		u8 *page;                                                     \
		u64 pageno = (state)->info[(state)->levels].pageno;           \
		u16 index = 0;                                                \
		bool is_in_scratch;                                           \
		page = hashtable_get(impl->hashtable, pageno);                \
		if (!page) {                                                  \
			is_in_scratch = false;                                \
			if (famdb_get_page(impl, &page, pageno) < 0) {        \
				return -1;                                    \
			}                                                     \
		} else                                                        \
			is_in_scratch = true;                                 \
		if (PAGE_IS_INTERNAL(page)) {                                 \
			index = INTERNAL_FIND_INDEX(page, key, key_len);      \
			u16 offset = PAGE_OFFSET_OF(page, index);             \
			pageno = *(u64 *)(page + offset);                     \
		}                                                             \
		(state)->info[(state)->levels].index = index;                 \
		(state)->info[(state)->levels].page = page;                   \
		(state)->info[(state)->levels].is_in_scratch = is_in_scratch; \
		(state)->info[(state)->levels + 1].pageno = pageno;           \
		(state)->levels++;                                            \
	})
#define LEAF_INSERT_IMPL(impl, data_off, state, key, key_len, value,           \
			 value_len)                                            \
	({                                                                     \
		u8 *page = (state)->info[(state)->levels - 1].page;            \
		u64 pageno = (state)->info[(state)->levels - 1].pageno;        \
		u16 total_bytes = PAGE_TOTAL_BYTES(page);                      \
		u16 needed = key_len + value_len + sizeof(u32) + sizeof(u16);  \
		if (needed + total_bytes > AVAILABLE(data_off) ||              \
		    PAGE_ELEMENTS(page) > MAX_ELEMENTS(data_off)) {            \
			u8 *rpage = NULL, *ppage = NULL;                       \
			i64 rpageno, ppageno;                                  \
			rpageno = BITMAP_ALLOC_PAGE(impl->db);                 \
			if (rpageno < 0) return -1;                            \
			HashtableEntry *nent =                                 \
			    ALLOC(impl, sizeof(HashtableEntry));               \
			if (!nent) {                                           \
				BITMAP_RELEASE_PAGE(impl->db, rpageno);        \
				return -1;                                     \
			}                                                      \
			nent->value.disk_pageno = rpageno;                     \
			nent->key = rpageno;                                   \
			hashtable_put(impl->hashtable, (void *)nent);          \
			rpage = nent->value.page;                              \
                                                                               \
			if ((state)->levels == 1) {                            \
				ppageno = BITMAP_ALLOC_PAGE(impl->db);         \
				if (ppageno < 0) {                             \
					BITMAP_RELEASE_PAGE(impl->db,          \
							    rpageno);          \
					return -1;                             \
				}                                              \
				nent = ALLOC(impl, sizeof(HashtableEntry));    \
				if (!nent) {                                   \
					BITMAP_RELEASE_PAGE(impl->db,          \
							    rpageno);          \
					BITMAP_RELEASE_PAGE(impl->db,          \
							    ppageno);          \
					return -1;                             \
				}                                              \
				nent->value.disk_pageno = ppageno;             \
				nent->key = ppageno;                           \
				hashtable_put(impl->hashtable, (void *)nent);  \
				ppage = nent->value.page;                      \
			} else {                                               \
				ppage =                                        \
				    (state)->info[(state)->levels - 2].page;   \
				ppageno =                                      \
				    (state)->info[(state)->levels - 2].pageno; \
			}                                                      \
			LEAF_SPLIT(page, data_off, rpage);                     \
			u16 left_elems = PAGE_ELEMENTS(page);                  \
			if ((state)->levels == 1)                              \
				INTERNAL_CREATE(                               \
				    ppage, data_off,                           \
				    LEAF_READ_KEY(page, left_elems - 1),       \
				    LEAF_KEY_LEN(page, left_elems - 1),        \
				    pageno, rpageno);                          \
			else                                                   \
				INTERNAL_INSERT(                               \
				    ppage, data_off,                           \
				    LEAF_READ_KEY(page, left_elems - 1),       \
				    LEAF_KEY_LEN(page, left_elems - 1),        \
				    (state)->info[(state)->levels - 2].index,  \
				    pageno, rpageno);                          \
			(state)->info[(state)->levels - 1].page =              \
			    LEAF_COMPARE_KEYS(page, left_elems - 1, key,       \
					      key_len) > 0                     \
				? rpage                                        \
				: page;                                        \
			if ((state)->levels == 1) impl->root = ppageno;        \
		}                                                              \
		LEAF_INSERT((state)->info[(state)->levels - 1].page, data_off, \
			    key, key_len, value, value_len);                   \
	})
#define BRING_TO_SCRATCH(impl, state)                                         \
	({                                                                    \
		for (i32 i = (state)->levels - 1; i >= 0; i--) {              \
			if (!(state)->info[i].is_in_scratch) {                \
				i64 npage = BITMAP_ALLOC_PAGE(impl->db);      \
				if (npage < 0) return -1;                     \
				HashtableEntry *nent =                        \
				    ALLOC(impl, sizeof(HashtableEntry));      \
				if (!nent) {                                  \
					BITMAP_RELEASE_PAGE(impl->db, npage); \
					return -1;                            \
				}                                             \
				nent->value.disk_pageno =                     \
				    (state)->info[i].pageno;                  \
				nent->key = npage;                            \
				hashtable_put(impl->hashtable, (void *)nent); \
				__builtin_memcpy(nent->value.page,            \
						 (state)->info[i].page,       \
						 PAGE_SIZE);                  \
				(state)->info[i].page = nent->value.page;     \
				if ((state)->info[i].pageno == impl->root)    \
					impl->root = npage;                   \
				(state)->info[i].pageno = nent->key;          \
			}                                                     \
		}                                                             \
	})

STATIC i32 famdb_init(FamDb *db) {
	if (BITMAP_ALLOC_PAGE(db) != db->fmap_pages) {
		errno = EINVAL;
		return -1;
	}
	SuperBlock *sb = (void *)db->map;
	u128 expected = 0;
	CommitUnion cu = {.commit.root = db->fmap_pages};
	return !__atomic_compare_exchange(&sb->commit.value, &expected,
					  &cu.value, false, __ATOMIC_SEQ_CST,
					  __ATOMIC_SEQ_CST);
}

STATIC i32 famdb_get_page(FamDbTxnImpl *impl, u8 **page, u64 page_num) {
	u8 *page_from_cache;
	i32 result = 0, res;
	u32 index, flags = IORING_ENTER_GETEVENTS;
	FamDb *db = impl->db;
	struct io_uring_sqe sqe = {.opcode = IORING_OP_READ,
				   .flags = IOSQE_FIXED_FILE,
				   .addr = (u64)impl->db->free_page,
				   .off = page_num * PAGE_SIZE,
				   .len = PAGE_SIZE,
				   .user_data = 1};

	if ((page_from_cache = lru_get(impl->db->cache, page_num)) != NULL) {
		*page = page_from_cache;
		return 0;
	}

	index = *db->sq_tail & *db->sq_mask;
	db->sq_array[index] = index;
	db->sqes[index] = sqe;

	__atomic_fetch_add(db->sq_tail, 1, __ATOMIC_SEQ_CST);
	res = io_uring_enter2(db->ring_fd, 1, 1, flags, NULL, 0);
	if (res < 0) {
		__atomic_fetch_sub(db->sq_tail, 1, __ATOMIC_SEQ_CST);
		return -1;
	}

	u32 idx = *db->cq_head & *db->cq_mask;
	result = db->cqes[idx].res;

	if (result < 0)
		errno = -result;
	else if (result != PAGE_SIZE) {
		errno = EIO;
		result = -1;
	}

	__atomic_fetch_add(db->cq_head, 1, __ATOMIC_SEQ_CST);

	u8 *tail = lru_tail(impl->db->cache);
	lru_put(impl->db->cache, page_num, impl->db->free_page);
	*page = impl->db->free_page;
	impl->db->free_page = tail;

	return result;
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

	db->fd = open(
	    config->pathname,
	    O_RDWR | O_NOATIME | O_CLOEXEC | (config->o_direct ? O_DIRECT : 0),
	    0);
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
		if (famdb_init(db) < 0) {
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

void famdb_txn_begin(FamDbTxn *txn, FamDb *db, FamDbScratch *scratch) {
	FamDbTxnImpl *impl = (void *)txn;
	impl->db = db;
	SuperBlock *sb = (void *)impl->db->map;
	impl->scratch = scratch;
	__builtin_memset(scratch->space, 0, scratch->capacity);

	impl->scratch_off = sizeof(void *) * db->config.scratch_hash_buckets +
			    sizeof(Hashtable) +
			    PAGE_SIZE * db->config.scratch_max_pages;
	impl->hashtable = (void *)(impl->scratch->space +
				   PAGE_SIZE * db->config.scratch_max_pages);
	hashtable_init(impl->hashtable, db->config.scratch_hash_buckets,
		       (void *)(impl->scratch->space +
				PAGE_SIZE * db->config.scratch_max_pages +
				sizeof(Hashtable)));
	impl->commit.value =
	    __atomic_load_n(&sb->commit.value, __ATOMIC_SEQ_CST);
	impl->root = impl->commit.commit.root;
}

i32 famdb_get(FamDbTxn *txn, const void *key, u16 key_len, void *value_out,
	      u32 value_out_capacity, u32 offset) {
	i32 ret = -1;
	FamDbTxnImpl *impl = (void *)txn;
	FamDbState state = {.info[0].pageno = impl->root};

	do GET_PAGE(impl, &state, key, key_len);
	while (PAGE_IS_INTERNAL(state.info[state.levels - 1].page));

	LEAF_FIND_MATCH(state.info[state.levels - 1].page, key, key_len,
			value_out, value_out_capacity, &ret);
	if (__builtin_expect(ret < 0, 0)) errno = ENOENT;
	return ret;
}

i32 famdb_set(FamDbTxn *txn, const void *key, u16 key_len, const void *value,
	      u32 value_len, u32 offset) {
	FamDbTxnImpl *impl = (void *)txn;
	FamDbState state = {.info[0].pageno = impl->root};

	do GET_PAGE(impl, &state, key, key_len);
	while (PAGE_IS_INTERNAL(state.info[state.levels - 1].page));
	BRING_TO_SCRATCH(impl, &state);
	LEAF_INSERT_IMPL(impl, 512, &state, key, key_len, value, value_len);
	return 0;
}

i32 famdb_del(FamDbTxn *txn, const void *key, u16 key_len);

i32 famdb_txn_commit(FamDbTxn *txn) {
	u32 index, flags = IORING_ENTER_GETEVENTS;
	FamDbTxnImpl *impl = (void *)txn;
	FamDb *db = impl->db;
	u64 size = sizeof(HashtableEntry), count = 0;

	for (u64 i = impl->scratch_off;
	     i > sizeof(void *) * impl->db->config.scratch_hash_buckets +
		     impl->db->config.scratch_max_pages * PAGE_SIZE +
		     sizeof(Hashtable);
	     i -= size) {
		HashtableEntry *ent =
		    (void *)(impl->scratch->space + i - sizeof(HashtableEntry));
		u64 npagenum = ent->key;
		u8 *page = ent->value.page;

		index = (*db->sq_tail + count) & *db->sq_mask;
		db->sq_array[index] = index;

		struct io_uring_sqe write_sqe = {.opcode = IORING_OP_WRITE,
						 .flags = IOSQE_FIXED_FILE,
						 .addr = (u64)page,
						 .off = npagenum * PAGE_SIZE,
						 .len = PAGE_SIZE,
						 .user_data = ++count};

		u8 *tail = lru_tail(impl->db->cache);
		__builtin_memcpy(impl->db->free_page, page, PAGE_SIZE);
		lru_put(impl->db->cache, npagenum, impl->db->free_page);
		impl->db->free_page = tail;

		db->sqes[index] = write_sqe;
	}

	__atomic_add_fetch(db->sq_tail, count, __ATOMIC_SEQ_CST);
	io_uring_enter2(db->ring_fd, count, count, flags, NULL, 0);
	__atomic_add_fetch(db->cq_head, count, __ATOMIC_SEQ_CST);

	struct io_uring_sqe sync_sqe = {.opcode = IORING_OP_FSYNC,
					.flags = IOSQE_FIXED_FILE,
					.fsync_flags = IORING_FSYNC_DATASYNC,
					.user_data = U64_MAX};
	index = (*db->sq_tail + count) & *db->sq_mask;
	db->sq_array[index] = index;
	db->sqes[index] = sync_sqe;
	__atomic_add_fetch(db->sq_tail, 1, __ATOMIC_SEQ_CST);
	io_uring_enter2(db->ring_fd, 1, 1, 0, NULL, 0);
	__atomic_add_fetch(db->cq_head, 1, __ATOMIC_SEQ_CST);

	CommitUnion commit = {.commit.seqno = impl->commit.commit.seqno + 1,
			      .commit.root = impl->root};

	SuperBlock *sb = (void *)db->map;
	u128 expected = impl->commit.value, desired = commit.value;
	i32 result = !__atomic_compare_exchange(
	    &sb->commit.value, &expected, &desired, false, __ATOMIC_SEQ_CST,
	    __ATOMIC_SEQ_CST);

	return result;
}

i32 famdb_create_scratch(FamDbScratch *scratch, u64 size) {
	scratch->space = map(size);
	if (!scratch->space) return -1;
	scratch->capacity = size;
	return 0;
}
void famdb_destroy_scratch(FamDbScratch *scratch) {
	if (scratch->space) munmap(scratch->space, scratch->capacity);
	scratch->space = NULL;
}

