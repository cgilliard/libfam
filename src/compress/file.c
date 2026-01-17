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

#include <libfam/atomic.h>
#include <libfam/builtin.h>
#include <libfam/compress.h>
#include <libfam/env.h>
#include <libfam/flags.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/syscall.h>
#include <libfam/utils.h>

#define MAX_PROCS 128

typedef struct {
	u64 next_chunk;
	u64 next_write;
	u64 chunks;
	u8 procs;
	i32 infd;
	u64 in_offset;
	i32 outfd;
	u64 out_offset;
	u32 err;
} CompressState;

typedef struct {
	u64 next_chunk;
	u64 next_write;
	u64 chunks;
	u8 procs;
	i32 infd;
	u64 in_offset;
	u64 in_len;
	i32 outfd;
	u64 out_offset;
	u64 *chunk_offsets;
	u64 chunk_offset_allocation;
	u32 err;
} DecompressState;

STATIC void compress_run_proc(u32 id, CompressState *state) {
	u8 buffers[2][MAX_COMPRESS_LEN + 3 + sizeof(u32)];
	u64 chunk;

	if (IS_VALGRIND()) fastmemset(buffers, 0, sizeof(buffers));
	while ((chunk = __aadd64(&state->next_chunk, 1)) < state->chunks) {
		i64 res = pread(state->infd, buffers[0], MAX_COMPRESS_LEN,
				state->in_offset + chunk * MAX_COMPRESS_LEN);
		if (res < 0) {
			__astore32(&state->err, errno == 0 ? EIO : errno);
			return;
		}
		i32 len =
		    compress_block(buffers[0], res, buffers[1] + sizeof(u32),
				   MAX_COMPRESS_LEN + 3);

		if (len < 0) {
			__astore32(&state->err, errno == 0 ? EIO : errno);
			return;
		}

		fastmemcpy(buffers[1], &len, sizeof(u32));
		u64 expected;
		do {
			expected = chunk;
			if (__aload32(&state->err)) return;
		} while (!__cas64(&state->next_write, &expected, U64_MAX));

		if (pwrite(state->outfd, buffers[1], len + sizeof(u32),
			   state->out_offset) < 0) {
			__astore64(&state->next_write, chunk + 1);
			__astore32(&state->err, errno == 0 ? EIO : errno);
			return;
		}
		__aadd64(&state->out_offset, len + sizeof(u32));
		__astore64(&state->next_write, chunk + 1);
	}
}

STATIC void decompress_run_proc(u32 id, DecompressState *state) {
	u8 buffers[2][MAX_COMPRESS_LEN + 3 + sizeof(u32)];
	u64 chunk;

	if (IS_VALGRIND()) fastmemset(buffers, 0, sizeof(buffers));
	while ((chunk = __aadd64(&state->next_chunk, 1)) < state->chunks) {
		u32 rlen = state->chunk_offsets[chunk + 1] -
			   state->chunk_offsets[chunk];
		if (rlen > MAX_COMPRESS_LEN + 3 + sizeof(u32)) {
			__astore32(&state->err, errno == 0 ? EPROTO : errno);
			return;
		}
		i32 res = pread(state->infd, buffers[0], rlen,
				state->chunk_offsets[chunk]);
		if (res < 0) {
			__astore32(&state->err, errno == 0 ? EIO : errno);
			return;
		}

		res = decompress_block(buffers[0], res, buffers[1],
				       MAX_COMPRESS_LEN + 3);
		if (res < 0) {
			__astore32(&state->err, errno == 0 ? EIO : errno);
			return;
		}
		u64 expected;
		do {
			expected = chunk;
			if (__aload32(&state->err)) return;
		} while (!__cas64(&state->next_write, &expected, U64_MAX));

		if (pwrite(state->outfd, buffers[1], res,
			   state->out_offset + MAX_COMPRESS_LEN * chunk) < 0) {
			__astore64(&state->next_write, chunk + 1);
			__astore32(&state->err, errno == 0 ? EIO : errno);
			return;
		}
		__astore64(&state->next_write, chunk + 1);
	}
}

STATIC i32 compress_setup_offsets(DecompressState *state, u64 st_size) {
	u64 offset = state->in_offset, i = 0, file_size = 0, chunk_len = 0;

	state->chunk_offset_allocation = 0;

	while (offset < state->in_len) {
		if (pread(state->infd, &chunk_len, sizeof(u32), offset) < 0)
			return -1;
		if ((i + 1) >= (state->chunk_offset_allocation / sizeof(u64))) {
			u64 *tmp = smap(4096 + state->chunk_offset_allocation);
			if (!tmp) return -1;
			fastmemcpy(tmp, state->chunk_offsets,
				   state->chunk_offset_allocation);
			munmap(state->chunk_offsets,
			       state->chunk_offset_allocation);
			state->chunk_offset_allocation += 4096;
			state->chunk_offsets = tmp;
		}
		state->chunk_offsets[i++] = offset + sizeof(u32);
		offset += chunk_len + sizeof(u32);
		if (chunk_len == 0) break;
		if (offset < state->in_len) file_size += MAX_COMPRESS_LEN;
	}
	state->chunks = i;
	state->chunk_offsets[i] = state->in_len;
	fallocate(state->outfd, file_size);

	return 0;
}

PUBLIC i32 compress_file(i32 infd, u64 in_offset, i32 outfd, u64 out_offset) {
	i32 ret = 0;
	CompressState *state = NULL;
	struct stat st, outst;
	state = smap(sizeof(CompressState));
	if (!state) return -1;
	if (fstat(infd, &st) < 0) return -1;
	if (fstat(outfd, &outst) < 0) return -1;
	if (st.st_size <= in_offset || !S_ISREG(st.st_mode) ||
	    !S_ISREG(outst.st_mode)) {
		errno = EINVAL;
		ret = -1;
		goto cleanup;
	}

	state->chunks = ((st.st_size - in_offset) + MAX_COMPRESS_LEN - 1) /
			MAX_COMPRESS_LEN;
	state->procs = min(get_physical_cores_cpuid(), state->chunks);
	state->procs = min(state->procs, MAX_PROCS);
	state->infd = infd;
	state->in_offset = in_offset;
	state->outfd = outfd;
	state->out_offset = out_offset;

	i32 pids[MAX_PROCS] = {0};
	u32 i;
	for (i = 0; i < (state->procs - 1); i++) {
		pids[i] = fork();
		if (pids[i] < 0) {
			ret = -1;
			goto cleanup;
		}
		if (!pids[i]) {
			compress_run_proc(i, state);
			exit_group(0);
		}
	}
	compress_run_proc(i, state);
	for (u32 i = 0; i < state->procs; i++) waitpid(pids[i]);
	if (state->err) {
		errno = state->err;
		ret = -1;
	}
cleanup:
	if (state) munmap(state, sizeof(CompressState));
	return ret;
}

PUBLIC i32 decompress_file(i32 infd, u64 in_offset, i32 outfd, u64 out_offset) {
	i32 ret = 0;
	DecompressState *state = NULL;
	struct stat st, outst;

	state = smap(sizeof(DecompressState));
	if (!state) {
		ret = -1;
		goto cleanup;
	}
	if (fstat(infd, &st) < 0 || fstat(outfd, &outst) < 0) {
		ret = -1;
		goto cleanup;
	}
	if (!st.st_size || st.st_size <= in_offset || !S_ISREG(st.st_mode) ||
	    !S_ISREG(outst.st_mode)) {
		errno = EINVAL;
		ret = -1;
		goto cleanup;
	}

	state->procs =
	    min(get_physical_cores_cpuid(),
		(st.st_size + (MAX_COMPRESS_LEN - 1) / MAX_COMPRESS_LEN));
	state->procs = min(state->procs, MAX_PROCS);
	state->infd = infd;
	state->in_offset = in_offset;
	state->in_len = st.st_size;
	state->outfd = outfd;
	state->out_offset = out_offset;

	if (compress_setup_offsets(state, st.st_size) < 0) {
		ret = -1;
		goto cleanup;
	}

	i32 pids[MAX_PROCS] = {0};

	u64 i;
	for (i = 0; i < (state->procs - 1); i++) {
		pids[i] = fork();
		if (pids[i] < 0) {
			ret = -1;
			goto cleanup;
		}
		if (!pids[i]) {
			decompress_run_proc(i, state);
			exit_group(0);
		}
	}

	decompress_run_proc(i, state);
	for (u32 i = 0; i < state->procs; i++) waitpid(pids[i]);

	if (state->err) {
		errno = state->err;
		ret = -1;
	}

cleanup:
	if (state) {
		if (state->chunk_offsets) {
			munmap(state->chunk_offsets,
			       state->chunk_offset_allocation);
		}
		munmap(state, sizeof(DecompressState));
	}
	return ret;
}

PUBLIC i32 compress_stream(i32 infd, u64 in_offset, i32 outfd, u64 out_offset) {
	i64 res, len, rlen, wlen, to_write;
	bool is_last = false, wbytes = false;
	u8 buffers[2][MAX_COMPRESS_LEN + 3 + sizeof(u32)];

	if (IS_VALGRIND()) fastmemset(buffers, 0, sizeof(buffers));

	while (!is_last) {
		rlen = 0;
		while (rlen < MAX_COMPRESS_LEN) {
			res = pread(infd, buffers[0] + rlen,
				    MAX_COMPRESS_LEN - rlen, in_offset + rlen);
			if (res < 0) return res;
			rlen += res;
			if (res == 0) {
				is_last = true;
				break;
			}
		}
		if (rlen == 0 && wbytes) break;
		wbytes = true;
		len = compress_block(buffers[0], rlen, buffers[1] + sizeof(u32),
				     MAX_COMPRESS_LEN + 3);
		fastmemcpy(buffers[1], &len, sizeof(u32));
		to_write = len + sizeof(u32);
		wlen = 0;
		while (wlen < to_write) {
			res = pwrite(outfd, buffers[1], to_write, out_offset);
			if (res < 0) {
				return res;
			}
			wlen += res;
		}
		out_offset += to_write;
		in_offset += MAX_COMPRESS_LEN;
	}

	return 0;
}

PUBLIC i32 decompress_stream(i32 infd, u64 in_offset, i32 outfd,
			     u64 out_offset) {
	u8 buffers[2][MAX_COMPRESS_LEN + 3 + sizeof(u32)];
	u64 rlen = 0;
	i64 res;
	u32 chunk_len = 0;

	if (IS_VALGRIND()) fastmemset(buffers, 0, sizeof(buffers));

	while (true) {
		res = pread(infd, &chunk_len, sizeof(u32), in_offset);
		if (res < 0) return res;
		if (res < sizeof(u32)) break;
		in_offset += sizeof(u32);
		rlen = 0;
		while (rlen < chunk_len) {
			res = pread(infd, buffers[0] + rlen, chunk_len - rlen,
				    in_offset);
			if (res < 0) return res;
			if (res == 0) break;
			rlen += res;
		}
		in_offset += chunk_len;
		if (!rlen) break;

		res = decompress_block(buffers[0], rlen, buffers[1],
				       MAX_COMPRESS_LEN + 3);
		if (res < 0) return res;
		i64 out_offset_update = res;
		while (res) {
			i64 wres = pwrite(outfd, buffers[1], res, out_offset);
			if (wres < 0) {
				return wres;
			}
			res -= wres;
		}

		out_offset += out_offset_update;
	}

	return 0;
}

