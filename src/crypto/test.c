#include <libfam/storm.h>
#include <libfam/test_base.h>

Bench(storm_init_perf) {
#define TRIALS 100000
	u64 cc, cc_sum = 0;
	__attribute__((aligned(32))) u8 block[32] = {0};
	StormContext ctx;
	for (u64 i = 0; i < TRIALS; i++) {
		__attribute__((aligned(32))) u8 key[32] = {0};
		__builtin_memcpy(key, &i, sizeof(u64));
		cc = cycle_counter();
		storm_init(&ctx, key);
		cc_sum += cycle_counter() - cc;
		storm_next_block(&ctx, block);
		ASSERT(*(u64 *)block, "rand");
	}
	const u8 *msg = "avg cycles (storm_init)=";
	pwrite(2, msg, __builtin_strlen(msg), 0);
	write_num(2, cc_sum / TRIALS);
	pwrite(2, "\n", 1, 0);
#undef TRIALS
}
