#include <libfam/format.h>
#include <libfam/fstatx.h>
#include <libfam/main.h>
#include <libfam/rng.h>
#include <libfam/storm.h>
#include <libfam/types.h>

#define VECTOR_FILE_PATH "/tmp/storm_vectors.h"
#define DEPTH 16
#define KEY_COUNT 32

int main(i32 argc, u8 **argv, u8 **envp) {
	StormContext ctx;
	Rng rng;
	rng_init(&rng);
	__attribute__((aligned(32))) u8 keys[KEY_COUNT][32] = {0};
	__attribute__((aligned(32))) u8 inputs[KEY_COUNT][DEPTH][32] = {0};
	rng_gen(&rng, keys, sizeof(keys));
	rng_gen(&rng, inputs, sizeof(inputs));
	println("Building storm vectors!");
	unlink(VECTOR_FILE_PATH);
	i32 fd = open(VECTOR_FILE_PATH, O_CREAT | O_RDWR, 0600);
	Formatter fmt = FORMATTER_INIT;
	FORMAT(&fmt, "#ifndef _STORM_VECTORS_H\n");
	FORMAT(&fmt, "#define _STORM_VECTORS_H\n");
	FORMAT(&fmt, "\ntypedef struct { \n");
	FORMAT(&fmt, "__attribute__((aligned(32))) u8 key[32]; \n");
	FORMAT(&fmt, "__attribute__((aligned(32))) u8 input[{}][32]; \n",
	       DEPTH);
	FORMAT(&fmt, "__attribute__((aligned(32))) u8 expected[{}][32]; \n",
	       DEPTH);
	FORMAT(&fmt, "} StormVector;\n\n");

	FORMAT(&fmt, "static const StormVector storm_vectors[] = {\n");

	for (u32 i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		FORMAT(&fmt, "\n  {\n    .key = {");
		for (u32 j = 0; j < 32; j++) {
			FORMAT(&fmt, "{}", keys[i][j]);
			if (j != 31) FORMAT(&fmt, ",");
		}
		FORMAT(&fmt, "},\n");
		FORMAT(&fmt, "    .input = {{\n");
		for (u32 j = 0; j < sizeof(inputs[i]) / sizeof(inputs[i][0]);
		     j++) {
			FORMAT(&fmt, "      {{");
			for (u32 k = 0; k < 32; k++) {
				FORMAT(&fmt, "{}", inputs[i][j][k]);
				if (k != 31) FORMAT(&fmt, ",");
			}
			FORMAT(&fmt, "}}");
			if (j != sizeof(inputs[i]) / sizeof(inputs[i][0]) - 1)
				FORMAT(&fmt, ",\n");
			else
				FORMAT(&fmt, "\n");
		}
		FORMAT(&fmt, "    }}\n,    .expected = {{\n");
		storm_init(&ctx, keys[i]);
		for (u32 j = 0; j < DEPTH; j++) {
			__attribute__((aligned(32))) u8 tmp[32];
			fastmemcpy(tmp, inputs[i][j], 32);
			storm_next_block(&ctx, tmp);
			FORMAT(&fmt, "      {{");
			for (u32 k = 0; k < 32; k++) {
				FORMAT(&fmt, "{}", tmp[k]);
				if (k != 31) FORMAT(&fmt, ",");
			}
			FORMAT(&fmt, "}}");
			if (j != sizeof(inputs[i]) / sizeof(inputs[i][0]) - 1)
				FORMAT(&fmt, ",\n");
			else
				FORMAT(&fmt, "\n");
		}
		FORMAT(&fmt, "    }}\n  }");
		if (i != sizeof(keys) / sizeof(keys[0]) - 1) FORMAT(&fmt, ",");
	}

	FORMAT(&fmt, "\n};\n");

	FORMAT(&fmt, "#endif /* _STORM_VECTORS_H */\n");
	const u8 *out = format_to_string(&fmt);

	i64 res = pwrite(fd, out, faststrlen(out), 0);
	println("res={},len={}", res, faststrlen(out));

	close(fd);
	return 0;
}

