// lmdb_bench.c
// Compile with: gcc -O3 -o lmdb_bench lmdb_bench.c -llmdb
// Run: ./lmdb_bench /tmp/lmdbtest 1000000

#include <lmdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define KEY_SIZE 16
#define VAL_SIZE 32
#define DB_PATH "/tmp/lmdb_bench"

static uint64_t get_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void die(const char *msg, int rc) {
	fprintf(stderr, "%s: %s\n", msg, mdb_strerror(rc));
	exit(EXIT_FAILURE);
}

static uint64_t cycle_counter(void) {
#if defined(__x86_64__)
	uint32_t lo, hi;
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	__asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
	uint64_t cnt;
	__asm__ __volatile__("isb" : : : "memory");
	__asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(cnt));
	return cnt;
#else
#error "Unsupported architecture"
#endif
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <db_path>\n", argv[0]);
		return 1;
	}

	const char *path = argv[1];
	size_t n = 10000;

	MDB_env *env = NULL;
	MDB_dbi dbi;
	MDB_txn *txn = NULL;
	MDB_val key, val;
	char kbuf[KEY_SIZE] = {0};
	char vbuf[VAL_SIZE] = {0};

	// Environment setup
	int rc = mdb_env_create(&env);
	if (rc) die("mdb_env_create", rc);

	rc = mdb_env_set_maxreaders(env, 126);
	if (rc) die("mdb_env_set_maxreaders", rc);

	rc = mdb_env_set_mapsize(env, 1ULL << 30);  // 1 GiB map
	if (rc) die("mdb_env_set_mapsize", rc);

	rc = mdb_env_open(env, path, MDB_NOSUBDIR | MDB_WRITEMAP, 0664);
	if (rc) die("mdb_env_open", rc);

	uint64_t start;
	uint64_t cycle_sum = 0;

	rc = mdb_txn_begin(env, NULL, 0, &txn);
	if (rc) die("mdb_txn_begin warm", rc);

	rc = mdb_dbi_open(txn, NULL, MDB_CREATE, &dbi);
	if (rc) die("mdb_dbi_open", rc);

	for (uint64_t i = 0; i < n; i++) {
		memcpy(kbuf, &i, sizeof(uint64_t));
		key.mv_size = KEY_SIZE;
		key.mv_data = kbuf;

		memset(vbuf, 0xAA, VAL_SIZE);
		val.mv_size = VAL_SIZE;
		val.mv_data = vbuf;

		start = cycle_counter();
		rc = mdb_put(txn, dbi, &key, &val, 0);
		cycle_sum += cycle_counter() - start;
		if (rc) die("mdb_put warm", rc);
	}

	rc = mdb_txn_commit(txn);
	if (rc) die("mdb_txn_commit warm", rc);

	printf("mdb_put avg cycles = %lu\n", cycle_sum / n);

	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (rc) die("mdb_txn_begin read", rc);

	cycle_sum = 0;
	uint64_t sum = 0;
	for (uint64_t i = 0; i < n; i++) {
		memcpy(kbuf, &i, sizeof(uint64_t));
		key.mv_size = KEY_SIZE;
		key.mv_data = kbuf;

		start = cycle_counter();
		rc = mdb_get(txn, dbi, &key, &val);
		cycle_sum += cycle_counter() - start;
		if (rc == MDB_NOTFOUND) die("not found", rc);
		if (rc) die("mdb_get", rc);

		sum += *(uint64_t *)val.mv_data;  // prevent optimization away
	}

	mdb_txn_abort(txn);

	printf("mdb_get avg cycles = %lu\n", cycle_sum / n);
	cycle_sum = 0;

	for (uint64_t i = 0; i < n; i++) {
		rc = mdb_txn_begin(env, NULL, 0, &txn);
		if (rc) die("txn_begin commit", rc);

		memcpy(kbuf, &i, sizeof(uint64_t));
		key.mv_size = KEY_SIZE;
		key.mv_data = kbuf;

		memset(vbuf, 0xBB, VAL_SIZE);
		val.mv_size = VAL_SIZE;
		val.mv_data = vbuf;

		rc = mdb_put(txn, dbi, &key, &val, 0);
		if (rc) die("mdb_put commit", rc);

		start = cycle_counter();
		rc = mdb_txn_commit(txn);
		cycle_sum += cycle_counter() - start;
		if (rc) die("mdb_txn_commit", rc);
	}

	printf("mdb_txn_commit avg cycles = %lu\n", cycle_sum / n);

	mdb_dbi_close(env, dbi);
	mdb_env_close(env);

	printf("\nDone.\n");
	return 0;
}
