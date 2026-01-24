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
#include <libfam/rng.h>
#include <libfam/test.h>

Bench(famdb) {
	unlink("resources/1mb.dat");
	i32 fd = open("resources/1mb.dat", O_CREAT | O_RDWR, 0600);
	ASSERT(fd > 0, "open");
	ASSERT(!fallocate(fd, 1024 * 1024), "fallocate");
	close(fd);

	i32 res;
	FamDb *db = NULL;
	FamDbTxn txn;
	u8 space[1024 * 512];
	FamDbScratch scratch = {.space = space, .capacity = sizeof(space)};
	FamDbConfig config = {
	    .queue_depth = 16,
	    .pathname = "resources/1mb.dat",
	    .lru_hash_buckets = 1024,
	    .lru_capacity = 512,
	    .debug_split_delete = true,
	};

	res = famdb_open(&db, &config);
	ASSERT(!res, "famdb_open");
	ASSERT(db, "db");
	ASSERT(!famdb_begin_txn(&txn, db, &scratch), "famdb_begin_txn");

#define TRIALS 1000000
	u64 cc_sum = 0;
	__attribute__((aligned(32))) u8 key[16] = {0};
	__attribute__((aligned(32))) u8 value[32] = {0};
	Rng rng;
	rng_init(&rng);

	for (u64 i = 0; i < TRIALS; i++) {
		rng_gen(&rng, key, 16);
		rng_gen(&rng, value, 32);
		u64 cc = cycle_counter();
		res =
		    famdb_set(&txn, key, sizeof(key), value, sizeof(value), 0);
		cc = cycle_counter() - cc;
		cc_sum += cc;
		ASSERT(!res, "famdb_set");
	}

	println("avg_put={} cycles", cc_sum / TRIALS);
	famdb_close(db);
#undef TRIALS
	unlink("resources/1mb.dat");
}

Test(famdb) {
#define SCRATCH_SIZE (2 * 1024 * 1024)
#define TRIALS 6000
	unlink("resources/4mb.dat");
	i32 fd = open("resources/4mb.dat", O_CREAT | O_RDWR, 0600);
	ASSERT(fd > 0, "open");
	ASSERT(!fallocate(fd, 1024 * 1024 * 1024), "fallocate");
	close(fd);

	Rng rng;
	i32 res;
	FamDb *db = NULL;
	FamDbTxn txn;
	u8 *space = map(SCRATCH_SIZE);
	FamDbScratch scratch = {.space = space, .capacity = SCRATCH_SIZE};
	FamDbConfig config = {.queue_depth = 512,
			      .pathname = "resources/4mb.dat",
			      .lru_hash_buckets = 16,
			      .lru_capacity = 150};

	res = famdb_open(&db, &config);
	ASSERT(!res, "famdb_open");
	ASSERT(db, "db");
	ASSERT(!famdb_begin_txn(&txn, db, &scratch), "famdb_begin_txn");

	__attribute__((aligned(32))) u8 keys[TRIALS][16] = {0};
	__attribute__((aligned(32))) u8 values[TRIALS][32] = {0};
	rng_init(&rng);
	u64 cc, cc_sum = 0;
	for (u64 i = 0; i < TRIALS; i++) {
		rng_gen(&rng, keys[i], 16);
		rng_gen(&rng, values[i], 32);
		for (u8 j = 0; j < 16; j++)
			keys[i][j] = (keys[i][j] % 26) + 'a';
		for (u8 j = 0; j < 32; j++)
			values[i][j] = (values[i][j] % 26) + 'a';
		cc = cycle_counter();
		res = famdb_set(&txn, keys[i], 16, values[i], 32, 0);
		cc_sum += cycle_counter() - cc;
		if (res) perror("famdb_set");
		ASSERT(!res, "famdb_set");
	}
	// println("famdb_set avg cycles = {}", cc_sum / TRIALS);

	cc = cycle_counter();
	famdb_txn_commit(&txn);
	cc = cycle_counter() - cc;
	f64 mcycles = (f64)cc / 1000000.0;
	u8 value_out[32] = {0};
	cc_sum = 0;
	for (u64 i = 0; i < TRIALS; i++) {
		cc = cycle_counter();
		res = famdb_get(&txn, keys[i], 16, value_out, 32, 0);
		cc_sum += cycle_counter() - cc;
		ASSERT_EQ(res, 32, "famdb_get {}", i);
		ASSERT(!memcmp(value_out, values[i], 32), "value");
	}
	ASSERT_EQ(famdb_get(&txn, "0123456789ABCDEF", 16, value_out, 32, 0), -1,
		  "not found");
	// println("famdb_get avg cycles = {}", cc_sum / TRIALS);
	(void)cc_sum;
	(void)mcycles;

	/*
	println("famdb_txn_commit cycles (large) = {} (million cycles)",
		mcycles);
		*/

	famdb_close(db);
	unlink("resources/4mb.dat");
	munmap(space, SCRATCH_SIZE);
#undef TRIALS
#undef SCRATCH_SIZE
}
