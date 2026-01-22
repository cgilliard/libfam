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
#include <libfam/test.h>

Test(famdb) {
	i32 res;
	FamDb *db = NULL;
	FamDbTxn txn;
	u8 space[1024 * 512];
	FamDbScratch scratch = {.space = space, .capacity = sizeof(space)};
	FamDbConfig config = {.queue_depth = 16,
			      .pathname = "resources/1mb.dat",
			      .lru_hash_buckets = 1024,
			      .lru_capacity = 512};

	res = famdb_open(&db, &config);
	ASSERT(!res, "famdb_open");
	ASSERT(db, "db");
	ASSERT(!famdb_begin_txn(&txn, db, &scratch), "famdb_begin_txn");

#define TRIALS 100
	u64 cc_sum = 0;
	for (u64 i = 0; i < TRIALS; i++) {
		u64 cc = cycle_counter();
		res = famdb_set(&txn, "abc", 3, "def", 3, 0);
		cc = cycle_counter() - cc;
		cc_sum += cc;
		ASSERT(!res, "famdb_put");
	}

	println("avg_put={} cycles", cc_sum / TRIALS);
	famdb_close(db);
}

Test(famdb_set) {
	i32 res;
	FamDb *db = NULL;
	FamDbTxn txn;
	u8 space[1024 * 512];
	FamDbScratch scratch = {.space = space, .capacity = sizeof(space)};
	FamDbConfig config = {.queue_depth = 16,
			      .pathname = "resources/1mb.dat",
			      .lru_hash_buckets = 1024,
			      .lru_capacity = 512};

	res = famdb_open(&db, &config);
	ASSERT(!res, "famdb_open");
	ASSERT(db, "db");
	ASSERT(!famdb_begin_txn(&txn, db, &scratch), "famdb_begin_txn");

	res = famdb_set(&txn, "abc", 3, "def", 3, 0);
	ASSERT(!res, "famdb_put");

	famdb_close(db);
}
