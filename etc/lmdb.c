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
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <db_path> <num_ops>\n", argv[0]);
		return 1;
	}

	const char *path = argv[1];
	size_t n = strtoull(argv[2], NULL, 10);
	if (n == 0) n = 1000000;

	MDB_env *env = NULL;
	MDB_dbi dbi;
	MDB_txn *txn = NULL;
	MDB_val key, val;
	char kbuf[KEY_SIZE];
	char vbuf[VAL_SIZE];

	// Environment setup
	int rc = mdb_env_create(&env);
	if (rc) die("mdb_env_create", rc);

	rc = mdb_env_set_maxreaders(env, 126);
	if (rc) die("mdb_env_set_maxreaders", rc);

	rc = mdb_env_set_mapsize(env, 1ULL << 30);  // 1 GiB map
	if (rc) die("mdb_env_set_mapsize", rc);

	rc = mdb_env_open(env, path, MDB_NOSUBDIR | MDB_WRITEMAP, 0664);
	if (rc) die("mdb_env_open", rc);

	// ----------------------------------------------------------------------
	// 1. Warm-up + cached random read benchmark
	// ----------------------------------------------------------------------
	printf("=== 1. Warm-up & cached random read benchmark (%zu ops) ===\n",
	       n);

	uint64_t start;
	uint64_t cycle_sum = 0;

	rc = mdb_txn_begin(env, NULL, 0, &txn);
	if (rc) die("mdb_txn_begin warm", rc);

	rc = mdb_dbi_open(txn, NULL, MDB_CREATE, &dbi);
	if (rc) die("mdb_dbi_open", rc);

	// Warm-up: write 1M keys
	for (size_t i = 0; i < n; i++) {
		snprintf(kbuf, sizeof(kbuf), "%016zx", i);
		key.mv_size = KEY_SIZE;
		key.mv_data = kbuf;

		memset(vbuf, 0xAA, VAL_SIZE);
		val.mv_size = VAL_SIZE;
		val.mv_data = vbuf;

		start = cycle_counter();
		rc = mdb_put(txn, dbi, &key, &val, 0);
		start = cycle_counter() - start;
		cycle_sum += start;
		if (rc) die("mdb_put warm", rc);
	}

	rc = mdb_txn_commit(txn);
	if (rc) die("mdb_txn_commit warm", rc);

	uint64_t t1 = cycle_sum;
	printf("Warm-up write cycles per op: %d\n", t1 / n);

	// Cached random read benchmark
	start = get_ns();

	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (rc) die("mdb_txn_begin read", rc);

	uint64_t sum = 0;
	for (size_t i = 0; i < n; i++) {
		snprintf(kbuf, sizeof(kbuf), "%016zx", i % n);
		key.mv_size = KEY_SIZE;
		key.mv_data = kbuf;

		rc = mdb_get(txn, dbi, &key, &val);
		if (rc == MDB_NOTFOUND) continue;
		if (rc) die("mdb_get", rc);

		sum += *(uint64_t *)val.mv_data;  // prevent optimization away
	}

	mdb_txn_abort(txn);

	uint64_t t2 = get_ns();
	double rps = n / ((t2 - start) / 1e9);
	double lat_us = (t2 - start) / (double)n / 1000.0;

	printf("Cached random read: %.0f ops/sec, %.1f µs avg latency\n", rps,
	       lat_us);

	// ----------------------------------------------------------------------
	// 2. Commit throughput benchmark (100k small commits)
	// ----------------------------------------------------------------------

	size_t ncommits = 1000;
	start = get_ns();

	for (size_t i = 0; i < ncommits; i++) {
		rc = mdb_txn_begin(env, NULL, 0, &txn);
		if (rc) die("txn_begin commit", rc);

		snprintf(kbuf, sizeof(kbuf), "%016zx", i);
		key.mv_size = KEY_SIZE;
		key.mv_data = kbuf;

		memset(vbuf, 0xBB, VAL_SIZE);
		val.mv_size = VAL_SIZE;
		val.mv_data = vbuf;

		rc = mdb_put(txn, dbi, &key, &val, 0);
		if (rc) die("mdb_put commit", rc);

		rc = mdb_txn_commit(txn);
		if (rc) die("mdb_txn_commit", rc);
	}

	uint64_t t3 = get_ns();
	double commit_tps = ncommits / ((t3 - start) / 1e9);
	double commit_latency_us = (t3 - start) / (double)ncommits / 1000.0;

	printf("Commit throughput: %.0f tps, %.1f µs avg commit latency\n",
	       commit_tps, commit_latency_us);

	mdb_dbi_close(env, dbi);
	mdb_env_close(env);

	printf("\nDone.\n");
	return 0;
}
