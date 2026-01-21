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
#include <libfam/linux.h>
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
	u8 *file_data;
	u64 fmap_pages;
	u64 total_pages;
	u64 bitmap_bits;
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

#define PAGE_TYPE_INTERNAL_FLAG (0x1 << 0)

#define FIRST_OFFSET 512
#define PAGE_IS_INTERNAL(page) ((page[0] & PAGE_TYPE_INTERNAL_FLAG))
#define PAGE_IS_LEAF(page) (!(page[0] & PAGE_TYPE_INTERNAL_FLAG))
#define PAGE_ELEMENTS(page) (((u16 *)page)[1])
#define PAGE_TOTAL_BYTES(page) (((u16 *)page)[2])
#define PAGE_OFFSET_OF(page, elem) (((u16 *)page)[elem + 3])
#define PAGE_KV_LEN(page, elem) \
	(((u32 *)(page + PAGE_OFFSET_OF(page, elem)))[0])
#define PAGE_READ_KEY_LEN(page, elem) \
	(((u16 *)(page + PAGE_OFFSET_OF(page, elem) + sizeof(u32)))[0])
#define PAGE_READ_KEY(page, elem) \
	(page + PAGE_OFFSET_OF(page, elem) + sizeof(u32) + sizeof(u16))
#define PAGE_READ_VALUE(page, elem)                                      \
	(page + PAGE_OFFSET_OF(page, elem) + sizeof(u32) + sizeof(u16) + \
	 PAGE_READ_KEY_LEN(page, elem))
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

#define PAGE_PRINT_ELEMENT(page, elem)                                        \
	({                                                                    \
		u8 key_out[1024] = {0}, value_out[1024] = {0};                \
		fastmemcpy(key_out, PAGE_READ_KEY(page, elem),                \
			   PAGE_READ_KEY_LEN(page, elem));                    \
		fastmemcpy(                                                   \
		    value_out, PAGE_READ_VALUE(page, elem),                   \
		    PAGE_KV_LEN(page, elem) - PAGE_READ_KEY_LEN(page, elem)); \
		println(                                                      \
		    "key[{}]={},key_len={},value[{}]={},kv_len={},offset={}", \
		    elem, key_out, PAGE_READ_KEY_LEN(page, elem), elem,       \
		    value_out, PAGE_KV_LEN(page, elem),                       \
		    PAGE_OFFSET_OF(page, elem));                              \
	})
#define PAGE_PRINT_ELEMENTS(page)                                              \
	({                                                                     \
		u64 elements = PAGE_ELEMENTS(page);                            \
		u64 total_bytes = PAGE_TOTAL_BYTES(page);                      \
		println("elements={},total_bytes={}", elements, total_bytes);  \
		println(                                                       \
		    "--------------------------------------------------------" \
		    "-------------------------------");                        \
		for (u32 i = 0; i < PAGE_ELEMENTS(page); i++) {                \
			PAGE_PRINT_ELEMENT(page, i);                           \
		}                                                              \
		println(                                                       \
		    "--------------------------------------------------------" \
		    "-------------------------------");                        \
	})

STATIC_ASSERT(sizeof(FamDbTxn) == sizeof(FamDbTxnImpl), fam_db_txn_size);

STATIC i32 famdb_init_db(FamDb *db) {
	SuperBlock *sb = (void *)db->file_data;
	__astore64(&sb->root, db->fmap_pages);
	return 0;
}

STATIC i32 famdb_write_page(FamDbTxnImpl *impl, u64 page_num,
			    const u8 buffer[PAGE_SIZE]) {
	i32 result;
	u32 index, cq_tail = 0, cq_head = 0;
	FamDb *db = impl->db;
	struct io_uring_sqe sqe = {.opcode = IORING_OP_WRITE,
				   .flags = IOSQE_FIXED_FILE,
				   .addr = (u64)buffer,
				   .off = page_num * PAGE_SIZE,
				   .len = PAGE_SIZE,
				   .user_data = 1};
	index = *db->sq_tail & *db->sq_mask;
	db->sq_array[index] = index;
	db->sqes[index] = sqe;
	__aadd32(db->sq_tail, 1);

	do {
		cq_tail = __aload32(db->cq_tail);
		cq_head = *db->cq_head;
		if (cq_tail == cq_head) continue;

		u32 idx = (cq_head) & *db->cq_mask;
		result = db->cqes[idx].res;

		if (result < 0 && cq_head != cq_tail) errno = -result;
	} while (cq_head == cq_tail);

	__aadd32(db->cq_head, 1);

	return result;
}

STATIC i32 famdb_read_page(FamDbTxnImpl *impl, u64 page_num,
			   u8 buffer[PAGE_SIZE], bool wakeup) {
	i32 result;
	u32 index, cq_tail = 0, cq_head = 0;
	u32 flags = IORING_ENTER_SQ_WAKEUP;
	FamDb *db = impl->db;
	struct io_uring_sqe sqe = {.opcode = IORING_OP_READ,
				   .flags = IOSQE_FIXED_FILE,
				   .addr = (u64)buffer,
				   .off = page_num * PAGE_SIZE,
				   .len = PAGE_SIZE,
				   .user_data = 1};

	index = *db->sq_tail & *db->sq_mask;
	db->sq_array[index] = index;
	db->sqes[index] = sqe;

	if (wakeup) {
		i32 res = io_uring_enter2(db->ring_fd, 0, 0, flags, NULL, 0);
		if (res < 0) return -1;
	}
	__aadd32(db->sq_tail, 1);

	do {
		cq_tail = __aload32(db->cq_tail);
		cq_head = *db->cq_head;
		if (cq_tail == cq_head) continue;

		u32 idx = (cq_head) & *db->cq_mask;
		result = db->cqes[idx].res;

		if (result < 0 && cq_head != cq_tail) errno = -result;

	} while (cq_head == cq_tail);

	__aadd32(db->cq_head, 1);

	return result;
}

i32 famdb_open(FamDb **dbret, const FamDbConfig *config) {
	FamDb *db;
	struct statx st;

	if (!config->queue_depth || !config->pathname) {
		errno = EINVAL;
		return -1;
	}

	db = map(sizeof(FamDb));
	if (!db) return -1;

	db->fd = open(config->pathname, O_RDWR, 0);
	if (db->fd < 0) {
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

	println("bitmap_bits={},fmap_pages={}", db->bitmap_bits,
		db->fmap_pages);

	db->file_data = fmap(db->fd, total_pages * PAGE_SIZE, 0);

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
			      (i32[]){db->fd}, 1) < 0) {
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
	if (db->fd > 0) close(db->fd);
	if (db->sq_ring) munmap(db->sq_ring, db->sq_ring_size);
	db->sq_ring = NULL;
	if (db->cq_ring) munmap(db->cq_ring, db->cq_ring_size);
	db->cq_ring = NULL;
	if (db->sqes) munmap(db->sqes, db->sqes_size);
	db->sqes = NULL;
	if (db->ring_fd > 0) raw_close(db->ring_fd);
	db->ring_fd = -1;
	if (db->file_data) munmap(db->file_data, db->total_pages * PAGE_SIZE);
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
	println("impl->root={}", impl->root);
	return 0;
}
i32 famdb_get(FamDbTxn *txn, const void *key, u64 key_len, void **value_out,
	      u64 *value_len_out) {
	return 0;
}

i32 famdb_put(FamDbTxn *txn, const void *key, u64 key_len, const void *value,
	      u64 value_len) {
	FamDbTxnImpl *impl = (void *)txn;
	u8 *page = impl->db->file_data + PAGE_SIZE * impl->root;
	for (u32 i = 0; i < 3; i++) {
		page = impl->db->file_data +
		       PAGE_SIZE * (impl->root + i * 40 + page[0]);
		if (page[0]) println("!0");
	}

	return 0;
}

i32 famdb_del(FamDbTxn *txn, const void *key, u64 key_len) { return 0; }
void famdb_txn_abort(FamDbTxn *txn) {}
i32 famdb_txn_commit(FamDbTxn *txn) { return 0; }

i32 famdb_cursor_open(FamDbCursor **cursor, FamDbTxn *txn,
		      CursorConfig config) {
	return 0;
}
i32 famdb_cursor_next(FamDbCursor *cur, void **key, u64 *keylen, void **val,
		      u64 *vallen) {
	return 0;
}
void famdb_cursor_close(FamDbCursor *cur) {}

