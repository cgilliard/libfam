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
} FamDbConfig;

typedef enum { CURSOR_FORWARD, CURSOR_BACKWARDS } CursorConfig;

i32 famdb_open(FamDb **db, const FamDbConfig *config);
void famdb_close(FamDb *db);
i32 famdb_begin_txn(FamDbTxn *txn, FamDb *db, FamDbScratch *scratch);
i32 famdb_get(FamDbTxn *txn, const void *key, u64 key_len, void **value_out,
	      u64 *value_len_out);
i32 famdb_put(FamDbTxn *txn, const void *key, u64 key_len, const void *value,
	      u64 value_len);
i32 famdb_del(FamDbTxn *txn, const void *key, u64 key_len);
void famdb_txn_abort(FamDbTxn *txn);
i32 famdb_txn_commit(FamDbTxn *txn);

i32 famdb_cursor_open(FamDbCursor **cursor, FamDbTxn *txn, CursorConfig config);
i32 famdb_cursor_next(FamDbCursor *cur, void **key, u64 *keylen, void **val,
		      u64 *vallen);
void famdb_cursor_close(FamDbCursor *cur);

#endif /* _FAMDB_H */
