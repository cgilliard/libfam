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

#ifndef _FAMDB_H
#define _FAMDB_H

#include <libfam/types.h>

#define FAM_DB_TXN_SIZE 256

typedef struct FamDb FamDb;

typedef struct FamDbTxn {
	u8 data[FAM_DB_TXN_SIZE];
} FamDbTxn;

typedef struct FamDbCursor FamDbCursor;

typedef struct {
	u8 *space;
	u64 capacity;
} FamDbScratch;

typedef struct {
	const u8 *pathname;
	i32 queue_depth;
	u64 lru_capacity;
	u64 lru_hash_buckets;
	u64 scratch_hash_buckets;
	u64 scratch_max_pages;
	u16 leaf_max_keys;
	u16 internal_max_keys;
#if TEST == 1
	bool debug_split_delete;
#endif /* TEST */
} FamDbConfig;

typedef enum { CURSOR_FORWARD, CURSOR_BACKWARDS } CursorConfig;

i32 famdb_open(FamDb **db, const FamDbConfig *config);
void famdb_close(FamDb *db);
void famdb_txn_begin(FamDbTxn *txn, FamDb *db, FamDbScratch *scratch);
i32 famdb_get(FamDbTxn *txn, const void *key, u16 key_len, void *value_out,
	      u32 value_out_capacity, u32 offset);
i32 famdb_set(FamDbTxn *txn, const void *key, u64 key_len, const void *value,
	      u64 value_len, u64 offset);
i32 famdb_del(FamDbTxn *txn, const void *key, u64 key_len);
i32 famdb_txn_commit(FamDbTxn *txn);

i32 famdb_cursor_open(FamDbCursor **cursor, FamDbTxn *txn, CursorConfig config);
i32 famdb_cursor_next(FamDbCursor *cur, void **key, u64 *keylen, void **val,
		      u64 *vallen);
void famdb_cursor_close(FamDbCursor *cur);

i32 famdb_create_scratch(FamDbScratch *scratch, u64 size);
void famdb_destroy_scratch(FamDbScratch *scratch);
i32 famdb_reclaim(FamDb *db);

#endif /* _FAMDB_H */
