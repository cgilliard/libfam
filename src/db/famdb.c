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

#define TAG_LEN 16

struct FamDb {
	FamDbConfig config;
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
	u64 hash_buckets;
	u64 last_free;
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
#define GET_PAGE(impl, pageno, is_modified)                          \
	({                                                           \
		Hashtable *h = (void *)impl->scratch->space;         \
		u8 *page = hashtable_get(h, pageno);                 \
		*is_modified = page != NULL;                         \
		if (!page) {                                         \
			if (famdb_get_page(impl, &page, pageno) < 0) \
				return -1;                           \
		}                                                    \
		page;                                                \
	})
#define LOAD_PAGE(impl, pageno)                                           \
	({                                                                \
		Hashtable *h = (void *)impl->scratch->space;              \
		u8 *page = hashtable_get(h, pageno);                      \
		if (!page) {                                              \
			HashtableKeyValue *kv;                            \
			u64 size = sizeof(HashtableKeyValue) + PAGE_SIZE; \
			if (famdb_get_page(impl, &page, pageno) < 0)      \
				return -1;                                \
			kv = ALLOC(impl, size);                           \
			if (!kv) return -1;                               \
			kv->key = pageno;                                 \
			fastmemcpy(kv->data, page, PAGE_SIZE);            \
			hashtable_put(h, kv);                             \
			page = kv->data;                                  \
		}                                                         \
		page;                                                     \
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
#define PAGE_COMPARE_KEYS_INTERNAL(page, key, key_len, elem)               \
	({                                                                 \
		u16 elem_key_off = PAGE_OFFSET_OF(page, elem);             \
		u16 elements = PAGE_ELEMENTS(page);                        \
		u16 elem_key_len = 0;                                      \
		if (elem >= elements - 1)                                  \
			elem_key_len = PAGE_TOTAL_BYTES(page) -            \
				       (elem_key_off + sizeof(u64));       \
		else                                                       \
			elem_key_len = PAGE_OFFSET_OF(page, elem + 1) -    \
				       (elem_key_off + sizeof(u64));       \
		u16 min_len = min(key_len, elem_key_len);                  \
		i32 cmp = fastmemcmp(                                      \
		    key, page + FIRST_OFFSET + elem_key_off + sizeof(u64), \
		    min_len);                                              \
		cmp != 0		 ? cmp                             \
		: key_len > elem_key_len ? 1                               \
		: key_len < elem_key_len ? -1                              \
					 : 0;                              \
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
#define PAGE_FIND_INDEX_INTERNAL(page, key, key_len)                         \
	({                                                                   \
		u16 min = 0, max = PAGE_ELEMENTS(page), mid;                 \
		i32 cmp;                                                     \
		while (min < max) {                                          \
			mid = min + ((max - min) >> 1);                      \
			cmp = PAGE_COMPARE_KEYS_INTERNAL(page, key, key_len, \
							 mid);               \
			if (cmp == 0) {                                      \
				min = mid;                                   \
				break;                                       \
			} else if (cmp < 0)                                  \
				max = mid;                                   \
			else                                                 \
				min = mid + 1;                               \
		}                                                            \
		min;                                                         \
	})
#define PAGE_READ_INTERNAL_INDEX(page, elem)                            \
	({                                                              \
		u16 _offset__ = PAGE_OFFSET_OF(page, elem);             \
		u64 _ret__ = *(u64 *)(page + FIRST_OFFSET + _offset__); \
		_ret__;                                                 \
	})
#define PAGE_SPLIT(page, lpage, rpage)                                         \
	({                                                                     \
		u16 page_elements = PAGE_ELEMENTS(page);                       \
		u16 total_bytes = PAGE_TOTAL_BYTES(page);                      \
		u16 left_elems = page_elements >> 1;                           \
		u16 right_elems = page_elements - left_elems;                  \
		((u16 *)lpage)[1] = left_elems;                                \
		((u16 *)rpage)[1] = right_elems;                               \
		u16 split_bytes =                                              \
		    PAGE_OFFSET_OF(page, left_elems) - FIRST_OFFSET;           \
		((u16 *)lpage)[2] = total_bytes - split_bytes;                 \
		((u16 *)rpage)[2] = total_bytes - ((u16 *)lpage)[2];           \
		fastmemcpy(((u16 *)lpage) + 3, ((u16 *)page) + 3,              \
			   left_elems << 1);                                   \
		fastmemcpy(((u16 *)rpage) + 3, ((u16 *)page) + 3 + left_elems, \
			   right_elems << 1);                                  \
		for (u16 i = 0; i < right_elems; i++)                          \
			((u16 *)rpage)[3 + i] -= split_bytes;                  \
		fastmemcpy(lpage + FIRST_OFFSET, page + FIRST_OFFSET,          \
			   split_bytes);                                       \
		fastmemcpy(rpage + FIRST_OFFSET,                               \
			   page + FIRST_OFFSET + split_bytes,                  \
			   total_bytes - split_bytes);                         \
	})
#define CREATE_INTERNAL_NODE(page, key, key_length, lpageno, rpageno)      \
	({                                                                 \
		((u16 *)page)[0] = PAGE_TYPE_INTERNAL_FLAG;                \
		((u16 *)page)[1] = 1;                                      \
		((u16 *)page)[2] = key_length + sizeof(u64) * 2;           \
		((u16 *)page)[3] = 0;                                      \
		((u16 *)page)[4] = key_length + sizeof(u64);               \
		*(u64 *)(page + FIRST_OFFSET) = lpageno;                   \
		*(u64 *)(page + FIRST_OFFSET + sizeof(u64) + key_length) = \
		    rpageno;                                               \
		fastmemcpy(page + FIRST_OFFSET + sizeof(u64), key,         \
			   key_length);                                    \
	})
#define INSERT_INTERNAL_NODE(page, key, key_length, lpageno, rpageno,         \
			     curpageno)                                       \
	({                                                                    \
		u16 elements = PAGE_ELEMENTS(page);                           \
		u16 _index__ =                                                \
		    PAGE_FIND_INDEX_INTERNAL(page, key, key_length);          \
		u16 elem_off = PAGE_OFFSET_OF(page, _index__);                \
		u16 cur_len;                                                  \
		if (_index__ == elements)                                     \
			cur_len = PAGE_OFFSET_OF(page, elements) -            \
				  PAGE_OFFSET_OF(page, elements - 1) -        \
				  sizeof(u64);                                \
		else                                                          \
			cur_len = ((u16 *)page)[3 + _index__ + 1] -           \
				  ((u16 *)page)[3 + _index__] - sizeof(u64);  \
		if (_index__ < elements) {                                    \
			u16 len_to_move = PAGE_TOTAL_BYTES(page) - elem_off;  \
			fastmemmove(page + elem_off + FIRST_OFFSET +          \
					key_length + sizeof(u64),             \
				    page + elem_off + FIRST_OFFSET,           \
				    len_to_move);                             \
		}                                                             \
		for (u16 i = _index__ + 1; i < elements + 1; i++) {           \
			((u16 *)page)[3 + i] += key_length - cur_len;         \
		}                                                             \
		((u16 *)page)[3 + elements + 1] =                             \
		    PAGE_TOTAL_BYTES(page) + key_length;                      \
		fastmemcpy(page + elem_off + FIRST_OFFSET + sizeof(u64), key, \
			   key_length);                                       \
		*(u64 *)(page + elem_off + FIRST_OFFSET) = lpageno;           \
		((u16 *)page)[1]++;                                           \
		((u16 *)page)[2] +=                                           \
		    key_length +                                              \
		    sizeof(u64); /*((u16 *)page)[3 + PAGE_ELEMENTS(page)] =   \
				     PAGE_TOTAL_BYTES(page) - sizeof(u64); */ \
		u16 next_offset = PAGE_OFFSET_OF(page, _index__ + 1);         \
		*(u64 *)(page + next_offset + FIRST_OFFSET) = rpageno;        \
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
#define PRINT_INTERNAL_ELEMENT(page, elem)                                 \
	({                                                                 \
		u8 tmpkey[1024] = {0};                                     \
		u64 _index__ = PAGE_READ_INTERNAL_INDEX(page, elem);       \
		u64 _offset__ = PAGE_OFFSET_OF(page, elem);                \
		u16 elem_key_off = PAGE_OFFSET_OF(page, elem);             \
		u16 elements = PAGE_ELEMENTS(page);                        \
		u16 elem_key_len = 0;                                      \
		if (elem >= elements - 1)                                  \
			elem_key_len = PAGE_TOTAL_BYTES(page) -            \
				       (elem_key_off + sizeof(u64) * 2);   \
		else                                                       \
			elem_key_len = PAGE_OFFSET_OF(page, elem + 1) -    \
				       (elem_key_off + sizeof(u64));       \
		if (elem >= elements) elem_key_len = 0;                    \
		fastmemcpy(tmpkey,                                         \
			   page + FIRST_OFFSET + _offset__ + sizeof(u64),  \
			   elem_key_len);                                  \
		println("index[{}]={} offset={},key={},elem_len={}", elem, \
			_index__, _offset__, tmpkey, elem_key_len);        \
	})
#define PRINT_INTERNAL_ELEMENTS(page)                                   \
	({                                                              \
		println(                                                \
		    "=========Printing internal page ({} elements, {} " \
		    "bytes)=========",                                  \
		    PAGE_ELEMENTS(page) + 1, PAGE_TOTAL_BYTES(page));   \
		for (u16 i = 0; i <= PAGE_ELEMENTS(page); i++)          \
			PRINT_INTERNAL_ELEMENT(page, i);                \
	})
#define GET_CHILD(page, elem)                                           \
	({                                                              \
		u64 _offset__ = PAGE_OFFSET_OF(page, elem);             \
		u64 pageno = *(u64 *)(page + FIRST_OFFSET + _offset__); \
		pageno;                                                 \
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
#define BITMAP_ALLOC_PAGE(db)                                               \
	({                                                                  \
		i64 ret = -1;                                               \
		u64 bit = 0, lw_offset, initial_offset = db->last_free;     \
		while (true) {                                              \
			lw_offset = db->last_free;                          \
			u64 *map_ptr = (u64 *)(db->file_data + PAGE_SIZE +  \
					       lw_offset * sizeof(u64));    \
			u64 cur = __aload64(map_ptr);                       \
			if (cur == U64_MAX) {                               \
				db->last_free = (db->last_free + 1) %       \
						(db->bitmap_bits >> 6);     \
				if (db->last_free == initial_offset) break; \
			} else {                                            \
				bit = __builtin_ctzll(~cur);                \
				u64 new = cur | (1UL << bit);               \
				if (__cas64(map_ptr, &cur, new)) {          \
					ret = bit + (lw_offset << 6) +      \
					      db->fmap_pages;               \
					break;                              \
				}                                           \
			}                                                   \
		}                                                           \
		ret;                                                        \
	})
#define BITMAP_RELEASE_PAGE(db, pageno)                                       \
	({                                                                    \
		if (pageno < db->fmap_pages) panic("Invalid page released!"); \
		u64 bit_offset = pageno - db->fmap_pages;                     \
		u64 cur;                                                      \
		u64 bit_to_zero = (1ULL << (bit_offset & 0x3F));              \
		u64 lw_offset = bit_offset >> 6;                              \
		u64 *map_ptr = (u64 *)(db->file_data + PAGE_SIZE +            \
				       lw_offset * sizeof(u64));              \
		do {                                                          \
			cur = __aload64(map_ptr);                             \
			if (!(cur & bit_to_zero))                             \
				panic("double free {}", pageno);              \
		} while (!__cas64(map_ptr, &cur, cur & ~bit_to_zero));        \
		db->last_free = lw_offset;                                    \
	})

STATIC i32 famdb_init_db(FamDb *db) {
	if (BITMAP_ALLOC_PAGE(db) != db->fmap_pages)
		panic("data file must be zeroed!");
	SuperBlock *sb = (void *)db->file_data;
	__astore64(&sb->root, db->fmap_pages);
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

i32 famdb_open(FamDb **dbret, const FamDbConfig *config) {
	FamDb *db;
	struct statx st = {0};

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

	db->bitmap_bits = (total_pages - db->fmap_pages) & ~63ULL;

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

	db->hash_buckets = 512;

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
	fastmemset(scratch->space, 0, scratch->capacity);

	impl->scratch_off =
	    sizeof(void *) * db->hash_buckets + sizeof(Hashtable);
	hashtable_init((void *)(impl->scratch->space), db->hash_buckets,
		       (void *)(impl->scratch->space + sizeof(Hashtable)));
	impl->db = db;
	sb = (void *)impl->db->file_data;
	impl->root = __aload64(&sb->root);
	return 0;
}

i32 famdb_get(FamDbTxn *txn, const void *key, u64 key_len, void *value_out,
	      u64 value_out_capacity, u64 offset) {
	FamDbTxnImpl *impl = (void *)txn;
	u8 *page;
	u64 pageno = impl->root;
	bool is_internal = false;
	bool is_modified;

	do {
		page = GET_PAGE(impl, pageno, &is_modified);
		is_internal = PAGE_IS_INTERNAL(page);
		if (is_internal) {
			u64 index =
			    PAGE_FIND_INDEX_INTERNAL(page, key, key_len);
			pageno = PAGE_READ_INTERNAL_INDEX(page, index);
		}
	} while (is_internal);

	u64 nindex = PAGE_FIND_INDEX(page, key, key_len);
	i32 cmp = PAGE_COMPARE_KEYS(page, key, key_len, nindex);
	if (cmp) {
		errno = ENOENT;
		return -1;
	}
	u64 value_len =
	    PAGE_KV_LEN(page, nindex) - PAGE_READ_KEY_LEN(page, nindex);
	u64 min_len = min(value_out_capacity, value_len);
	fastmemcpy(value_out, PAGE_READ_VALUE(page, nindex), min_len);

	return min_len;
}

i32 famdb_set(FamDbTxn *txn, const void *key, u64 key_len, const void *value,
	      u64 value_len, u64 offset) {
	u64 chain[128] = {0};
	u64 level = 0;
	FamDbTxnImpl *impl = (void *)txn;
	u8 *page;
	u64 pageno = impl->root;
	bool is_internal = false;
	bool is_modified;

	do {
		page = GET_PAGE(impl, pageno, &is_modified);
		is_internal = PAGE_IS_INTERNAL(page);
		if (is_internal) {
			u64 index =
			    PAGE_FIND_INDEX_INTERNAL(page, key, key_len);
			chain[level++] = pageno;
			pageno = PAGE_READ_INTERNAL_INDEX(page, index);
		}
	} while (is_internal);

	if (!is_modified) {
		Hashtable *h = (void *)impl->scratch->space;
		i64 npage = BITMAP_ALLOC_PAGE(impl->db);
		if (npage < 0) return -1;
		HashtableKeyValue *kv;
		u64 size =
		    sizeof(HashtableKeyValue) + PAGE_SIZE + 2 * sizeof(u64);
		kv = ALLOC(impl, size);
		if (!kv) return -1;
		kv->key = pageno;
		fastmemcpy(kv->data, page, PAGE_SIZE);
		fastmemcpy(kv->data + PAGE_SIZE, &npage, sizeof(u64));
		fastmemcpy(kv->data + PAGE_SIZE + sizeof(u64), &pageno,
			   sizeof(u64));
		hashtable_put(h, kv);
		page = kv->data;
	}

	if (FIRST_OFFSET + PAGE_TOTAL_BYTES(page) + key_len + value_len >
	    PAGE_SIZE - TAG_LEN) {
		if (impl->db->config.debug_split_delete) {
			fastmemset(page, 0, PAGE_SIZE);
		} else {
			Hashtable *h = (void *)impl->scratch->space;
			HashtableKeyValue *kv;
			u64 size = sizeof(HashtableKeyValue) + PAGE_SIZE +
				   2 * sizeof(u64);

			i64 rpagenum = BITMAP_ALLOC_PAGE(impl->db);
			if (rpagenum < 0) return -1;
			i64 lpagenum = BITMAP_ALLOC_PAGE(impl->db);
			if (lpagenum < 0) return -1;

			u8 *lpage = GET_PAGE(impl, lpagenum, &is_modified);
			if (!lpage) return -1;
			u8 *rpage = GET_PAGE(impl, rpagenum, &is_modified);
			if (!rpage) return -1;

			kv = ALLOC(impl, size);
			if (!kv) return -1;
			kv->key = lpagenum;
			fastmemcpy(kv->data, lpage, PAGE_SIZE);
			fastmemcpy(kv->data + PAGE_SIZE, &lpagenum,
				   sizeof(u64));
			fastmemcpy(kv->data + PAGE_SIZE + sizeof(u64),
				   &lpagenum, sizeof(u64));
			lpage = kv->data;
			hashtable_put(h, kv);

			kv = ALLOC(impl, size);
			if (!kv) return -1;
			kv->key = rpagenum;
			fastmemcpy(kv->data, rpage, PAGE_SIZE);
			fastmemcpy(kv->data + PAGE_SIZE, &rpagenum,
				   sizeof(u64));
			fastmemcpy(kv->data + PAGE_SIZE + sizeof(u64),
				   &rpagenum, sizeof(u64));
			rpage = kv->data;
			hashtable_put(h, kv);

			i64 ppagenum;
			u8 *ppage;

			if (level == 0) {
				ppagenum = BITMAP_ALLOC_PAGE(impl->db);
				if (ppagenum < 0) return -1;

				ppage = GET_PAGE(impl, ppagenum, &is_modified);
				if (!ppage) return -1;

				kv = ALLOC(impl, size);
				if (!kv) return -1;
				kv->key = ppagenum;
				fastmemcpy(kv->data, ppage, PAGE_SIZE);
				fastmemcpy(kv->data + PAGE_SIZE, &ppagenum,
					   sizeof(u64));
				fastmemcpy(kv->data + PAGE_SIZE + sizeof(u64),
					   &ppagenum, sizeof(u64));
				ppage = kv->data;
				hashtable_put(h, kv);
			} else {
				ppagenum = chain[level - 1];
				ppage = GET_PAGE(impl, ppagenum, &is_modified);
			}

			PAGE_SPLIT(page, lpage, rpage);
			u16 last = PAGE_ELEMENTS(lpage) - 1;
			if (level == 0) {
				CREATE_INTERNAL_NODE(
				    ppage, PAGE_READ_KEY(lpage, last),
				    PAGE_READ_KEY_LEN(lpage, last), lpagenum,
				    rpagenum);

				impl->root = ppagenum;
			} else {
				INSERT_INTERNAL_NODE(
				    ppage, PAGE_READ_KEY(lpage, last),
				    PAGE_READ_KEY_LEN(lpage, last), lpagenum,
				    rpagenum, pageno);
			}
			i32 cmp = PAGE_COMPARE_KEYS(lpage, key, key_len, last);
			page = cmp < 0 ? lpage : rpage;
		}
	}

	u64 nindex = PAGE_FIND_INDEX(page, key, key_len);
	PAGE_INSERT_BEFORE(page, nindex, key, key_len, value, value_len);

	return 0;
}

