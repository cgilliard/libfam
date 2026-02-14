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
#include <libfam/file.h>
#include <libfam/rng.h>
#include <libfam/test.h>

Test(famdb1) {
#define SCRATCH_SIZE (8 * 1024 * 1024)
#define DB_MEGABYTES 4
#define DB_FILE "resources/famdb1.dat"
	unlink(DB_FILE);
	i32 fd = open(DB_FILE, O_CREAT | O_RDWR, 0600);
	u8 value_out[1024] = {0};
	ASSERT(fd > 0, "open");
	ASSERT(!fallocate(fd, DB_MEGABYTES * 1024 * 1024), "fallocate");
	close(fd);

	i32 res;
	FamDbTxn txn;
	FamDbScratch scratch;
	FamDb *db = NULL;
	FamDbConfig config = {
	    .queue_depth = 16,
	    .pathname = DB_FILE,
	    .lru_hash_buckets = 1024,
	    .lru_capacity = 512,
	    .debug_split_delete = true,
	    .scratch_hash_buckets = 512,
	    .scratch_max_pages = 256,
	};

	res = famdb_open(&db, &config);
	ASSERT(!res, "famdb_open");
	ASSERT(db, "db");

	ASSERT(!famdb_create_scratch(&scratch, SCRATCH_SIZE), "scratch");
	famdb_txn_begin(&txn, db, &scratch);

	res = famdb_set(&txn, "abc", 3, "def1", 4, 0);
	ASSERT(!res, "famdb_set1");
	ASSERT(!famdb_set(&txn, "x", 1, "aaa", 3, 0), "famdb_set2");

	ASSERT_EQ(famdb_get(&txn, "abc", 3, value_out, sizeof(value_out), 0), 4,
		  "famdb_get");
	ASSERT(!memcmp(value_out, "def1", 4), "equal1");
	ASSERT_EQ(famdb_get(&txn, "x", 1, value_out, sizeof(value_out), 0), 3,
		  "famdb_get2");
	ASSERT(!memcmp(value_out, "aaa", 3), "equal2");

	famdb_destroy_scratch(&scratch);
	famdb_close(db);
	unlink(DB_FILE);
#undef SCRATCH_SIZE
#undef DB_MEGABYTES
#undef DB_FILE
}

void famdb_print(FamDbTxn *txn);

Test(famdb2) {
#define TRIALS 8
#define SCRATCH_SIZE (8 * 1024 * 1024)
#define DB_MEGABYTES 4
#define DB_FILE "/tmp/famdb2.dat"
	unlink(DB_FILE);
	i32 fd = open(DB_FILE, O_CREAT | O_RDWR, 0600);
	u8 value_out[1024] = {0};
	ASSERT(fd > 0, "open");
	ASSERT(!fallocate(fd, DB_MEGABYTES * 1024 * 1024), "fallocate");
	close(fd);

	i32 res;
	FamDbTxn txn;
	FamDbScratch scratch;
	FamDb *db = NULL;
	FamDbConfig config = {
	    .queue_depth = 1024,
	    .pathname = DB_FILE,
	    .lru_hash_buckets = 1024,
	    .lru_capacity = 512,
	    .debug_split_delete = true,
	    .scratch_hash_buckets = 512,
	    .scratch_max_pages = 256,
	};

	res = famdb_open(&db, &config);
	ASSERT(!res, "famdb_open");
	ASSERT(db, "db");

	__attribute__((aligned(32))) u8 keys[TRIALS][17] = {0};
	__attribute__((aligned(32))) u8 values[TRIALS][17] = {0};
	Rng rng;

	rng_init(&rng);

	ASSERT(!famdb_create_scratch(&scratch, SCRATCH_SIZE), "scratch");
	famdb_txn_begin(&txn, db, &scratch);

	for (u32 i = 0; i < TRIALS; i++) {
		rng_gen(&rng, keys[i], 16);
		rng_gen(&rng, values[i], 16);
		for (u8 j = 0; j < 16; j++)
			keys[i][j] = 'A' + (keys[i][j] % 26);
		for (u8 j = 0; j < 16; j++)
			values[i][j] = 'A' + (keys[i][j] % 26);
	}

	for (u32 i = 0; i < TRIALS; i++) {
		println("i={}", i);
		ASSERT(!famdb_set(&txn, keys[i], 16, values[i], 16, 0),
		       "famdb set {}", i);
		famdb_print(&txn);
	}

	for (u32 i = 0; i < TRIALS; i++) {
		ASSERT_EQ(famdb_get(&txn, keys[i], 16, value_out,
				    sizeof(value_out), 0),
			  16, "famdb_get1 {}", i);
		ASSERT(!memcmp(value_out, values[i], 16), "equal");
	}

	ASSERT_EQ(famdb_get(&txn, "p", 1, value_out, sizeof(value_out), 0), -1,
		  "not found");

	famdb_destroy_scratch(&scratch);
	famdb_close(db);
	unlink(DB_FILE);
#undef TRIALS
#undef SCRATCH_SIZE
#undef DB_MEGABYTES
#undef DB_FILE
}

