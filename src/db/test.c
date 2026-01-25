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
#include <libfam/linux.h>
#include <libfam/test.h>

Test(famdb1) {
#define SCRATCH_SIZE (2 * 1024 * 1024)
#define DB_MEGABYTES 4
#define TRIALS 6000
#define DB_FILE "/tmp/famdb1.dat"
	unlink(DB_FILE);
	i32 fd = open(DB_FILE, O_CREAT | O_RDWR, 0600);
	ASSERT(fd > 0, "open");
	ASSERT(!fallocate(fd, DB_MEGABYTES * 1024 * 1024), "fallocate");
	close(fd);

	i32 res;
	FamDb *db = NULL;
	FamDbTxn txn;
	FamDbScratch scratch;
	ASSERT(!famdb_create_scratch(&scratch, SCRATCH_SIZE),
	       "famdb_create_scratch");
	FamDbConfig config = {
	    .queue_depth = 16,
	    .pathname = DB_FILE,
	    .lru_hash_buckets = 1024,
	    .lru_capacity = 512,
	    .debug_split_delete = true,
	    .scratch_hash_buckets = 512,
	};

	res = famdb_open(&db, &config);
	ASSERT(!res, "famdb_open");
	ASSERT(db, "db");

	famdb_txn_begin(&txn, db, &scratch);

	ASSERT(!famdb_set(&txn, "0123456789012345", 16,
			  "0123456789012345"
			  "0123456789012340",
			  32, 0),
	       "famdb_set");

	ASSERT(!famdb_set(&txn, "0123456789012349", 16,
			  "0123456789012345"
			  "0123456789012349",
			  32, 0),
	       "famdb_set2");

	ASSERT(!famdb_set(&txn, "0123456789012342", 16,
			  "0123456789012345"
			  "0123456789012342",
			  32, 0),
	       "famdb_set3");

	ASSERT(!famdb_txn_commit(&txn), "commit");

	famdb_close(db);
	db = NULL;
	res = famdb_open(&db, &config);
	ASSERT(!res, "famdb_open2");
	ASSERT(db, "db2");

	famdb_txn_begin(&txn, db, &scratch);
	ASSERT(!famdb_set(&txn, "012345678901234a", 16,
			  "0123456789012345"
			  "0123456789012345",
			  32, 0),
	       "famdb_set4");

	u8 value_out[1024] = {0};

	ASSERT_EQ(famdb_get(&txn, "012345678901234a", 16, value_out,
			    sizeof(value_out), 0),
		  32, "fam_get1");
	ASSERT(!memcmp(value_out,
		       "0123456789012345"
		       "0123456789012345",
		       32),
	       "value_out");

	errno = 0;
	perror("pre");
	res = famdb_get(&txn, "0123456789012342", 16, value_out,
			sizeof(value_out), 0);
	perror("famdb_get2");
	println("res2={}", res);
	ASSERT_EQ(res, 32, "fam_get2");
	ASSERT(!memcmp(value_out,
		       "0123456789012345"
		       "0123456789012342",
		       32),
	       "value_out");

	ASSERT(!famdb_txn_commit(&txn), "commit");

	famdb_close(db);
	famdb_destroy_scratch(&scratch);

	errno = 0;
	println("x {}", errno);
	perror("println");
}
