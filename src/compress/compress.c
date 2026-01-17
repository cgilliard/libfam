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

#include <libfam/builtin.h>
#include <libfam/compress.h>
#include <libfam/debug.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/utils.h>

#ifdef __AVX2__
#include <immintrin.h>
#endif /* __AVX2__ */

#define MAX_MATCH_LEN 256
#define MIN_MATCH_LEN 4
#define MAX_CODE_LENGTH 11
#define MAX_BOOK_CODE_LENGTH 7
#define MAX_BOOK_CODES (MAX_CODE_LENGTH + 4)
#define SYMBOL_TERM 256
#define MATCH_OFFSET (SYMBOL_TERM + 1)
#define MAX_MATCH_CODE 127
#define SYMBOL_COUNT (MATCH_OFFSET + MAX_MATCH_CODE + 1)
#define HASH_CONSTANT 0x9e3779b9U
#define LEN_SHIFT 4
#define DIST_MASK 0xF
#define REPEAT_VALUE_INDEX (MAX_CODE_LENGTH + 1)
#define REPEAT_ZERO_LONG_INDEX (MAX_CODE_LENGTH + 2)
#define REPEAT_ZERO_SHORT_INDEX (MAX_CODE_LENGTH + 3)

typedef struct {
	u16 code;
	u16 length;
} CodeLength;

typedef struct HuffmanNode {
	u16 symbol;
	u64 freq;
	struct HuffmanNode *left, *right;
} HuffmanNode;

typedef struct {
	HuffmanNode *nodes[SYMBOL_COUNT * 2 + 1];
	u64 size;
} HuffmanMinHeap;

typedef struct {
	u16 symbol;
	u8 length;
} HuffmanLookup;

#define SET_HASH(table, in, i) \
	table[((*(u32 *)((in) + (i))) * HASH_CONSTANT) >> 16] = i;

#define MATCH_CODE(len, dist) \
	(((31 - clz_u32((len) - 3)) << LEN_SHIFT) | (31 - clz_u32(dist)))

#define LEN_EXTRA_BITS(mc) ((mc) >> LEN_SHIFT)
#define DIST_EXTRA_BITS(mc) ((mc) & DIST_MASK)
#define LEN_BASE(mc) ((1 << ((mc) >> LEN_SHIFT)) - 1)
#define DIST_BASE(mc) (1 << ((mc) & DIST_MASK))
#define LEN_EXTRA_BITS_VALUE(code, actual_length) \
	(actual_length - LEN_BASE(code) - 4)
#define DIST_EXTRA_BITS_VALUE(code, actual_distance) \
	((actual_distance) - (1 << ((code) & DIST_MASK)))

#define FLUSH_STREAM(buffer, bits_in_buffer, out_bit_offset, data)            \
	do {                                                                  \
		u64 bit_offset = out_bit_offset & 0x7;                        \
		u64 byte_pos = out_bit_offset >> 3;                           \
		__builtin_prefetch(data + byte_pos, 1, 3);                    \
		out_bit_offset += bits_in_buffer;                             \
		u64 bits_to_write = 8 - bit_offset;                           \
		bits_to_write = min(bits_to_write, bits_in_buffer);           \
		u8 new_bits = (u8)(buffer & bitstream_masks[bits_to_write]);  \
		new_bits <<= bit_offset;                                      \
		u8 mask = bitstream_partial_masks[bit_offset][bits_to_write]; \
		u8 current_byte = data[byte_pos];                             \
		data[byte_pos] = (current_byte & mask) | new_bits;            \
		buffer >>= bits_to_write;                                     \
		bits_in_buffer -= bits_to_write;                              \
		byte_pos++;                                                   \
		u64 bits_mask = bitstream_masks[bits_in_buffer];              \
		u64 *data64 = (u64 *)(data + byte_pos);                       \
		u64 existing = *data64;                                       \
		*data64 = (existing & ~bits_mask) | (buffer & bits_mask);     \
		buffer = bits_in_buffer = 0;                                  \
	} while (0);

#define WRITE(buffer, bits_in_buffer, out_bit_offset, data, value, len)      \
	do {                                                                 \
		if ((bits_in_buffer) + (len) > 64)                           \
			FLUSH_STREAM(buffer, bits_in_buffer, out_bit_offset, \
				     data);                                  \
		buffer |= ((u64)(value) << (bits_in_buffer));                \
		(bits_in_buffer) += (len);                                   \
	} while (0);

#define TRY_LOAD(buffer, bits_in_buffer, in_bit_offset, data, capacity)     \
	{                                                                   \
		u64 bit_offset = in_bit_offset;                             \
		u64 bits_to_load = 64 - bits_in_buffer;                     \
		u64 end_byte = (bit_offset + bits_to_load + 7) >> 3;        \
		u64 byte_pos = bit_offset >> 3;                             \
		u8 bit_remainder = bit_offset & 0x7;                        \
		u64 bytes_needed = end_byte - byte_pos;                     \
		if (__builtin_expect(end_byte > capacity, 0)) {             \
			errno = EOVERFLOW;                                  \
			return -1;                                          \
		}                                                           \
		u64 new_bits = *(u64 *)(data + byte_pos);                   \
		u64 high = bytes_needed == 9 ? (u64)data[byte_pos + 8] : 0; \
		new_bits = (new_bits >> bit_remainder) |                    \
			   (high << (64 - bit_remainder));                  \
		new_bits &= bitstream_masks[bits_to_load];                  \
		buffer |= (new_bits << bits_in_buffer);                     \
		in_bit_offset += bits_to_load;                              \
		bits_in_buffer += bits_to_load;                             \
	}

#define TRY_READ(buffer, bits_in_buffer, in_bit_offset, data, capacity,       \
		 num_bits)                                                    \
	({                                                                    \
		if ((bits_in_buffer) < (num_bits)) {                          \
			TRY_LOAD(buffer, bits_in_buffer, in_bit_offset, data, \
				 capacity);                                   \
		}                                                             \
		u64 _res__ = buffer & (bitstream_masks[num_bits]);            \
		buffer = buffer >> num_bits;                                  \
		bits_in_buffer -= num_bits;                                   \
		_res__;                                                       \
	})

#define PEEK_READER(buffer, num_bits) (buffer & (bitstream_masks[num_bits]))
#define ADVANCE_READER(buffer, bits_in_buffer, num_bits) \
	do {                                             \
		buffer = buffer >> (num_bits);           \
		bits_in_buffer -= (num_bits);            \
	} while (0);

static const u8 bitstream_partial_masks[8][9] = {
    {255, 254, 252, 248, 240, 224, 192, 128, 0},
    {255, 253, 249, 241, 225, 193, 129, 1, 1},
    {255, 251, 243, 227, 195, 131, 3, 3, 3},
    {255, 247, 231, 199, 135, 7, 7, 7, 7},
    {255, 239, 207, 143, 15, 15, 15, 15, 15},
    {255, 223, 159, 31, 31, 31, 31, 31, 31},
    {255, 191, 63, 63, 63, 63, 63, 63, 63},
    {255, 127, 127, 127, 127, 127, 127, 127, 127}};

static const u64 bitstream_masks[65] = {
    0x0000000000000000ULL, 0x0000000000000001ULL, 0x0000000000000003ULL,
    0x0000000000000007ULL, 0x000000000000000FULL, 0x000000000000001FULL,
    0x000000000000003FULL, 0x000000000000007FULL, 0x00000000000000FFULL,
    0x00000000000001FFULL, 0x00000000000003FFULL, 0x00000000000007FFULL,
    0x0000000000000FFFULL, 0x0000000000001FFFULL, 0x0000000000003FFFULL,
    0x0000000000007FFFULL, 0x000000000000FFFFULL, 0x000000000001FFFFULL,
    0x000000000003FFFFULL, 0x000000000007FFFFULL, 0x00000000000FFFFFULL,
    0x00000000001FFFFFULL, 0x00000000003FFFFFULL, 0x00000000007FFFFFULL,
    0x0000000000FFFFFFULL, 0x0000000001FFFFFFULL, 0x0000000003FFFFFFULL,
    0x0000000007FFFFFFULL, 0x000000000FFFFFFFULL, 0x000000001FFFFFFFULL,
    0x000000003FFFFFFFULL, 0x000000007FFFFFFFULL, 0x00000000FFFFFFFFULL,
    0x00000001FFFFFFFFULL, 0x00000003FFFFFFFFULL, 0x00000007FFFFFFFFULL,
    0x0000000FFFFFFFFFULL, 0x0000001FFFFFFFFFULL, 0x0000003FFFFFFFFFULL,
    0x0000007FFFFFFFFFULL, 0x000000FFFFFFFFFFULL, 0x000001FFFFFFFFFFULL,
    0x000003FFFFFFFFFFULL, 0x000007FFFFFFFFFFULL, 0x00000FFFFFFFFFFFULL,
    0x00001FFFFFFFFFFFULL, 0x00003FFFFFFFFFFFULL, 0x00007FFFFFFFFFFFULL,
    0x0000FFFFFFFFFFFFULL, 0x0001FFFFFFFFFFFFULL, 0x0003FFFFFFFFFFFFULL,
    0x0007FFFFFFFFFFFFULL, 0x000FFFFFFFFFFFFFULL, 0x001FFFFFFFFFFFFFULL,
    0x003FFFFFFFFFFFFFULL, 0x007FFFFFFFFFFFFFULL, 0x00FFFFFFFFFFFFFFULL,
    0x01FFFFFFFFFFFFFFULL, 0x03FFFFFFFFFFFFFFULL, 0x07FFFFFFFFFFFFFFULL,
    0x0FFFFFFFFFFFFFFFULL, 0x1FFFFFFFFFFFFFFFULL, 0x3FFFFFFFFFFFFFFFULL,
    0x7FFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};

STATIC u32 find_matches(const u8 *in, u32 len,
			u16 match_array[MAX_COMPRESS_LEN + 2],
			u32 frequencies[SYMBOL_COUNT], u8 *out) {
	u32 i = 0, max, maitt = 0, out_bit_offset = 0;
	u64 buffer = 0, bits_in_buffer = 0;
	u8 *data = out + sizeof(u32);
	u16 table[1 << 16] = {0};

	max = len >= 32 + MAX_MATCH_LEN ? len - (32 + MAX_MATCH_LEN) : 0;

	while (i < max) {
		u32 key = *(u32 *)(in + i);
		u16 entry = (key * HASH_CONSTANT) >> 16;
		u16 dist = (u16)i - table[entry];
		table[entry] = i;
		u16 len = 0;
		u32 mpos = i - dist;
		if (dist) {
#ifdef __AVX2__
			u32 mask;
			do {
				__m256i vec1 = _mm256_loadu_si256(
				    (__m256i *)(in + mpos + len));
				__m256i vec2 = _mm256_loadu_si256(
				    (__m256i *)(in + i + len));
				__m256i cmp = _mm256_cmpeq_epi8(vec1, vec2);
				mask = _mm256_movemask_epi8(cmp);

				len += (mask != 0xFFFFFFFF) * ctz_u32(~mask) +
				       (mask == 0xFFFFFFFF) * 32;
			} while (mask == 0xFFFFFFFF && len < MAX_MATCH_LEN);
#else
			while (len < MAX_MATCH_LEN &&
			       in[i + len] == in[mpos + len])
				len++;
#endif /* !__AVX2__ */
		}
		if (len >= MIN_MATCH_LEN) {
			u8 mc = MATCH_CODE(len, dist);
			u8 extra_sum = LEN_EXTRA_BITS(mc) + DIST_EXTRA_BITS(mc);
			u64 combined_extra =
			    ((u32)DIST_EXTRA_BITS_VALUE(mc, dist)
			     << LEN_EXTRA_BITS(mc)) |
			    LEN_EXTRA_BITS_VALUE(mc, len);
			if (__builtin_expect(bits_in_buffer + extra_sum > 64,
					     0))
				FLUSH_STREAM(buffer, bits_in_buffer,
					     out_bit_offset, data);

			buffer |= combined_extra << bits_in_buffer;
			bits_in_buffer += extra_sum;

			u16 match_symbol = (u16)mc + MATCH_OFFSET;
			frequencies[match_symbol]++;
			match_array[maitt++] = match_symbol;
			SET_HASH(table, in, i + 1);
			SET_HASH(table, in, i + 2);
			SET_HASH(table, in, i + 3);
			i += len;
		} else {
			frequencies[in[i]]++;
			match_array[maitt++] = in[i++];
		}
	}
	while (i < len) {
		frequencies[in[i]]++;
		match_array[maitt++] = in[i++];
	}

	FLUSH_STREAM(buffer, bits_in_buffer, out_bit_offset, data);
	fastmemcpy(out, &out_bit_offset, sizeof(u32));

	match_array[maitt] = SYMBOL_TERM;
	frequencies[SYMBOL_TERM]++;
	return out_bit_offset;
}

STATIC void compress_init_node(HuffmanNode *node, u16 symbol, u64 freq) {
	node->symbol = symbol;
	node->freq = freq;
	node->left = node->right = NULL;
}

STATIC void compress_swap_nodes(HuffmanNode **a, HuffmanNode **b) {
	HuffmanNode *temp = *a;
	*a = *b;
	*b = temp;
}

STATIC void compress_heapify(HuffmanMinHeap *heap, u64 idx) {
	u64 smallest = idx;
	u64 left = 2 * idx + 1;
	u64 right = 2 * idx + 2;

	if (left < heap->size &&
	    heap->nodes[left]->freq < heap->nodes[smallest]->freq)
		smallest = left;
	if (right < heap->size &&
	    heap->nodes[right]->freq < heap->nodes[smallest]->freq)
		smallest = right;

	if (smallest != idx) {
		compress_swap_nodes(&heap->nodes[idx], &heap->nodes[smallest]);
		compress_heapify(heap, smallest);
	}
}

STATIC void compress_insert_heap(HuffmanMinHeap *heap, HuffmanNode *node) {
	u64 i = ++heap->size - 1;
	heap->nodes[i] = node;

	while (i && heap->nodes[(i - 1) / 2]->freq > heap->nodes[i]->freq) {
		compress_swap_nodes(&heap->nodes[i], &heap->nodes[(i - 1) / 2]);
		i = (i - 1) / 2;
	}
}

STATIC HuffmanNode *compress_extract_min(HuffmanMinHeap *heap) {
	HuffmanNode *min;
	if (heap->size == 0) return NULL;

	min = heap->nodes[0];
	heap->nodes[0] = heap->nodes[heap->size - 1];
	heap->size--;
	compress_heapify(heap, 0);

	return min;
}

STATIC void compress_compute_lengths(HuffmanNode *node, u8 length,
				     CodeLength *code_lengths) {
	if (!node) return;
	if (!node->left && !node->right)
		code_lengths[node->symbol].length = length;
	compress_compute_lengths(node->left, length + 1, code_lengths);
	compress_compute_lengths(node->right, length + 1, code_lengths);
}

STATIC void compress_build_tree(const u32 *frequencies,
				CodeLength *code_lengths, u16 count,
				HuffmanMinHeap *heap, HuffmanNode *nodes) {
	i32 i;
	u16 node_counter = 0;

	heap->size = 0;

	for (i = 0; i < count; i++) {
		if (frequencies[i]) {
			HuffmanNode *next = &nodes[node_counter++];
			compress_init_node(next, i, frequencies[i]);
			compress_insert_heap(heap, next);
		}
	}

	if (heap->size == 1) {
		HuffmanNode *node = compress_extract_min(heap);
		code_lengths[node->symbol].length = 1;
	} else {
		while (heap->size > 1) {
			HuffmanNode *left = compress_extract_min(heap);
			HuffmanNode *right = compress_extract_min(heap);
			HuffmanNode *parent = &nodes[node_counter++];
			compress_init_node(parent, 0xFFFF,
					   left->freq + right->freq);
			parent->left = left;
			parent->right = right;
			compress_insert_heap(heap, parent);
		}
	}
}

STATIC void compress_limit_lengths(const u32 *frequencies,
				   CodeLength *code_lengths, u16 count,
				   u8 max_length) {
	i32 i;
	u32 excess = 0;
	u32 needed = 0;

	for (i = 0; i < count; i++) {
		if (code_lengths[i].length > max_length) {
			excess += (code_lengths[i].length - max_length) *
				  frequencies[i];
			code_lengths[i].length = max_length;
			needed += frequencies[i];
		}
	}

	while (excess > 0 && needed > 0) {
		for (i = 0; i < count && excess > 0; i++) {
			if (code_lengths[i].length > 0 &&
			    code_lengths[i].length < max_length &&
			    frequencies[i] > 0) {
				u32 delta = (excess < frequencies[i])
						? excess
						: frequencies[i];
				code_lengths[i].length++;
				excess -= delta;
				needed -= delta;
			}
		}
	}

	u64 sum = 0;
	for (i = 0; i < count; i++)
		if (code_lengths[i].length > 0)
			sum += 1ULL << (max_length - code_lengths[i].length);

	while (sum > (1ULL << max_length)) {
		u16 best = 0;
		u32 min_freq = U32_MAX;
		for (u16 i = 0; i < count; ++i) {
			if (code_lengths[i].length > 1 &&
			    code_lengths[i].length < max_length &&
			    frequencies[i] < min_freq) {
				min_freq = frequencies[i];
				best = i;
			}
		}
		if (min_freq == U32_MAX) break;

		u8 old_len = code_lengths[best].length;
		code_lengths[best].length++;

		sum -= (1ULL << (max_length - old_len));
		sum += (1ULL << (max_length - code_lengths[best].length));
	}
}

STATIC void compress_calculate_lengths(const u32 *frequencies,
				       CodeLength *code_lengths, u16 count,
				       u8 max_length) {
	HuffmanMinHeap heap;
	HuffmanNode nodes[count * 2 + 1];
	HuffmanNode *root;
	compress_build_tree(frequencies, code_lengths, count, &heap, nodes);
	if ((root = compress_extract_min(&heap)) != NULL) {
		compress_compute_lengths(root, 0, code_lengths);
		compress_limit_lengths(frequencies, code_lengths, count,
				       max_length);
	}
}

STATIC void compress_calculate_codes(CodeLength *code_lengths, u16 count) {
	u32 i, j, code = 0;
	u32 length_count[MAX_CODE_LENGTH + 1] = {0};
	u32 length_start[MAX_CODE_LENGTH + 1] = {0};
	u32 length_pos[MAX_CODE_LENGTH + 1] = {0};

	for (i = 0; i < count; i++) {
		length_count[code_lengths[i].length]++;
	}

	for (i = 1; i <= MAX_CODE_LENGTH; i++) {
		code <<= 1;
		length_start[i] = code;
		code += length_count[i];
	}

	for (i = 0; i < count; i++) {
		if (code_lengths[i].length != 0) {
			u8 len = code_lengths[i].length;
			code_lengths[i].code =
			    length_start[len] + length_pos[len]++;
			code_lengths[i].code &= (1U << len) - 1;

			u16 reversed = 0;
			u16 temp = code_lengths[i].code;
			for (j = 0; j < len; j++) {
				reversed = (reversed << 1) | (temp & 1);
				temp >>= 1;
			}
			code_lengths[i].code = reversed;
		}
	}
}

STATIC void compress_build_code_book(
    const CodeLength code_lengths[SYMBOL_COUNT],
    CodeLength book[MAX_BOOK_CODES], u32 frequencies[MAX_BOOK_CODES]) {
	u8 last_length = 0;
	for (u16 i = 0; i < SYMBOL_COUNT; i++) {
		if (code_lengths[i].length) {
			if (last_length == code_lengths[i].length && i > 0) {
				u16 repeat = 1;
				while (i + repeat < SYMBOL_COUNT &&
				       code_lengths[i + repeat].length ==
					   last_length &&
				       repeat < 6) {
					repeat++;
				}
				if (repeat >= 3) {
					frequencies[REPEAT_VALUE_INDEX]++;
					i += repeat - 1;
					last_length = 0;
					continue;
				}
			}
			last_length = code_lengths[i].length;
			frequencies[code_lengths[i].length]++;
		} else {
			u16 run = i + 1;
			while (run < SYMBOL_COUNT &&
			       code_lengths[run].length == 0)
				run++;
			run -= i;

			if (run >= 11) {
				run = run > 138 ? 127 : run - 11;
				i += run + 10;
				frequencies[REPEAT_ZERO_LONG_INDEX]++;
			} else if (run >= 3) {
				run = run - 3;
				i += run + 2;
				frequencies[REPEAT_ZERO_SHORT_INDEX]++;
			} else
				frequencies[0]++;
			last_length = 0;
		}
	}
	compress_calculate_lengths(frequencies, book, MAX_BOOK_CODES,
				   MAX_BOOK_CODE_LENGTH);
	compress_calculate_codes(book, MAX_BOOK_CODES);
}

STATIC i32 compress_write(const CodeLength code_lengths[SYMBOL_COUNT],
			  const CodeLength book[MAX_BOOK_CODES],
			  const u16 match_array[MAX_COMPRESS_LEN + 2], u8 *out,
			  u32 out_bit_offset) {
	u32 i;
	u64 buffer = 0, bits_in_buffer = 0;
	u8 last_length = 0;
	u8 *data = out + sizeof(u32);
	for (i = 0; i < MAX_BOOK_CODES; i++) {
		WRITE(buffer, bits_in_buffer, out_bit_offset, data,
		      book[i].length, 3);
	}
	for (i = 0; i < SYMBOL_COUNT; i++) {
		if (code_lengths[i].length) {
			if (last_length == code_lengths[i].length) {
				u16 repeat = 1;
				while (i + repeat < SYMBOL_COUNT &&
				       code_lengths[i + repeat].length ==
					   last_length &&
				       repeat < 6) {
					repeat++;
				}
				if (repeat >= 3) {
					WRITE(buffer, bits_in_buffer,
					      out_bit_offset, data,
					      book[REPEAT_VALUE_INDEX].code,
					      book[REPEAT_VALUE_INDEX].length);
					WRITE(buffer, bits_in_buffer,
					      out_bit_offset, data, repeat - 3,
					      2);
					i += repeat - 1;
					last_length = 0;
					continue;
				}
			}

			WRITE(buffer, bits_in_buffer, out_bit_offset, data,
			      book[code_lengths[i].length].code,
			      book[code_lengths[i].length].length);
			last_length = code_lengths[i].length;
		} else {
			u16 run = i + 1;
			while (run < SYMBOL_COUNT &&
			       code_lengths[run].length == 0)
				run++;
			run -= i;
			if (run >= 11) {
				run = run > 138 ? 127 : run - 11;
				WRITE(buffer, bits_in_buffer, out_bit_offset,
				      data, book[REPEAT_ZERO_LONG_INDEX].code,
				      book[REPEAT_ZERO_LONG_INDEX].length);
				WRITE(buffer, bits_in_buffer, out_bit_offset,
				      data, run, 7);
				i += run + 10;
			} else if (run >= 3) {
				run = run - 3;
				WRITE(buffer, bits_in_buffer, out_bit_offset,
				      data, book[REPEAT_ZERO_SHORT_INDEX].code,
				      book[REPEAT_ZERO_SHORT_INDEX].length);
				WRITE(buffer, bits_in_buffer, out_bit_offset,
				      data, run, 3);
				i += run + 2;
			} else
				WRITE(buffer, bits_in_buffer, out_bit_offset,
				      data, book[0].code, book[0].length);

			last_length = 0;
		}
	}

	i = 0;
	while (match_array[i] != SYMBOL_TERM) {
		u16 symbol = match_array[i++];
		u16 code = code_lengths[symbol].code;
		u8 length = code_lengths[symbol].length;
		WRITE(buffer, bits_in_buffer, out_bit_offset, data, code,
		      length);
	}
	WRITE(buffer, bits_in_buffer, out_bit_offset, data,
	      code_lengths[SYMBOL_TERM].code, code_lengths[SYMBOL_TERM].length);
	WRITE(buffer, bits_in_buffer, out_bit_offset, data, 0, 64);
	WRITE(buffer, bits_in_buffer, out_bit_offset, data, 0, 64);
	FLUSH_STREAM(buffer, bits_in_buffer, out_bit_offset, data);

	return (out_bit_offset + 7) / 8;
}

STATIC void compress_build_lookup_table(const CodeLength *code_lengths,
					u16 count, HuffmanLookup *lookup_table,
					u8 max_length) {
	i32 i, j;
	for (i = 0; i < count; i++) {
		if (code_lengths[i].length) {
			i32 index = code_lengths[i].code &
				    ((1U << code_lengths[i].length) - 1);
			i32 fill_depth =
			    1U << (max_length - code_lengths[i].length);
			for (j = 0; j < fill_depth; j++) {
				lookup_table[index |
					     (j << code_lengths[i].length)]
				    .length = code_lengths[i].length;
				lookup_table[index |
					     (j << code_lengths[i].length)]
				    .symbol = i;
			}
		}
	}
}

STATIC i32 compress_read_block(const u8 *in, u32 len, u8 *out, u32 capacity) {
	CodeLength code_lengths[SYMBOL_COUNT] = {0};
	u32 i;
	u32 in_bit_offset;
	u64 buffer = 0;
	u32 bits_in_buffer = 0;
	CodeLength book_code_lengths[MAX_BOOK_CODES] = {0};
	u16 last_length = 0;
	HuffmanLookup book_lookup_table[(1U << MAX_BOOK_CODE_LENGTH)] = {0};

	if (len < sizeof(u32)) {
		errno = EOVERFLOW;
		return -1;
	}

	fastmemcpy(&in_bit_offset, in, sizeof(u32));

	in_bit_offset += 32;
	for (i = 0; i < MAX_BOOK_CODES; i++) {
		book_code_lengths[i].length =
		    TRY_READ(buffer, bits_in_buffer, in_bit_offset, in, len, 3);
	}

	compress_calculate_codes(book_code_lengths, MAX_BOOK_CODES);
	compress_build_lookup_table(book_code_lengths, MAX_BOOK_CODES,
				    book_lookup_table, MAX_BOOK_CODE_LENGTH);

	i = 0;
	errno = EPROTO;
	while (i < SYMBOL_COUNT) {
		if (bits_in_buffer < MAX_BOOK_CODE_LENGTH) {
			TRY_LOAD(buffer, bits_in_buffer, in_bit_offset, in,
				 len);
		}
		u8 bits = PEEK_READER(buffer, MAX_BOOK_CODE_LENGTH);
		HuffmanLookup entry = book_lookup_table[bits];
		u16 code = entry.symbol;
		ADVANCE_READER(buffer, bits_in_buffer, entry.length);
		if (code < REPEAT_VALUE_INDEX) {
			code_lengths[i++].length = code;
			last_length = code;
		} else if (code == REPEAT_VALUE_INDEX) {
			if (i == 0 || last_length == 0) return -1;
			u8 repeat = TRY_READ(buffer, bits_in_buffer,
					     in_bit_offset, in, len, 2) +
				    3;
			if (i + repeat > SYMBOL_COUNT) return -1;
			for (u32 j = 0; j < repeat; j++) {
				code_lengths[i++].length = last_length;
			}
		} else if (code == REPEAT_ZERO_LONG_INDEX) {
			u8 zeros = TRY_READ(buffer, bits_in_buffer,
					    in_bit_offset, in, len, 7) +
				   11;
			if (i + zeros > SYMBOL_COUNT) errno = EPROTO;
			for (u32 j = 0; j < zeros; j++)
				code_lengths[i++].length = 0;
		} else if (code == REPEAT_ZERO_SHORT_INDEX) {
			u8 zeros = TRY_READ(buffer, bits_in_buffer,
					    in_bit_offset, in, len, 3) +
				   3;
			if (i + zeros > SYMBOL_COUNT) return -1;
			for (u32 j = 0; j < zeros; j++)
				code_lengths[i++].length = 0;
		}
	}
	errno = SUCCESS;

	compress_calculate_codes(code_lengths, SYMBOL_COUNT);

	u32 itt = 0;
	u32 extra_bits_offset = 32, extra_bits_bits_in_buffer = 0;
	u64 extra_bits_buffer = 0;

	HuffmanLookup lookup_table[(1U << MAX_CODE_LENGTH)] = {0};
	compress_build_lookup_table(code_lengths, SYMBOL_COUNT, lookup_table,
				    MAX_CODE_LENGTH);

	while (true) {
		if (__builtin_expect(bits_in_buffer < MAX_CODE_LENGTH, 0))
			TRY_LOAD(buffer, bits_in_buffer, in_bit_offset, in,
				 len);
		u16 bits = PEEK_READER(buffer, MAX_CODE_LENGTH);
		HuffmanLookup entry = lookup_table[bits];
		u16 symbol = entry.symbol;
		ADVANCE_READER(buffer, bits_in_buffer, entry.length);
		if (__builtin_expect(symbol < SYMBOL_TERM, 0)) {
			if (itt >= capacity) {
				errno = EOVERFLOW;
				return -1;
			}
			out[itt++] = symbol;
		} else if (__builtin_expect(symbol == SYMBOL_TERM, 0)) {
			break;
		} else {
			u8 mc = entry.symbol - MATCH_OFFSET;
			u8 deb = DIST_EXTRA_BITS(mc);
			u8 leb = LEN_EXTRA_BITS(mc);
			u32 dist = DIST_BASE(mc);
			u16 mlen = LEN_BASE(mc) + 4;
			if (__builtin_expect(extra_bits_bits_in_buffer < 22,
					     0)) {
				TRY_LOAD(extra_bits_buffer,
					 extra_bits_bits_in_buffer,
					 extra_bits_offset, in, len);
			}
			mlen += PEEK_READER(extra_bits_buffer, leb);
			ADVANCE_READER(extra_bits_buffer,
				       extra_bits_bits_in_buffer, leb);
			dist += PEEK_READER(extra_bits_buffer, deb);
			ADVANCE_READER(extra_bits_buffer,
				       extra_bits_bits_in_buffer, deb);
			if (__builtin_expect(
				mlen + 32 + itt > capacity || dist > itt, 0)) {
				errno = EOVERFLOW;
				return -1;
			}
			u8 *out_dst = out + itt;
			u8 *out_src = out + itt - dist;
			itt += mlen;
#ifdef __AVX2__
			if (__builtin_expect(out_src + 32 <= out_dst, 1)) {
				u64 chunks = (mlen + 31) >> 5;
				while (chunks--) {
					__m256i vec = _mm256_loadu_si256(
					    (__m256i *)out_src);
					_mm256_storeu_si256((__m256i *)out_dst,
							    vec);
					out_src += 32;
					out_dst += 32;
				}
			} else if (__builtin_expect(out_src + 16 <= out_dst,
						    1)) {
				u64 chunks = (mlen + 15) >> 4;
				while (chunks--) {
					__m128i vec =
					    _mm_loadu_si128((__m128i *)out_src);
					_mm_storeu_si128((__m128i *)out_dst,
							 vec);
					out_src += 16;
					out_dst += 16;
				}
			} else if (__builtin_expect(out_src + 8 <= out_dst,
						    1)) {
				u64 chunks = (mlen + 7) >> 3;
				while (chunks--) {
					*((u64 *)out_dst) = *((u64 *)out_src);
					out_src += 8;
					out_dst += 8;
				}
			} else {
				while (mlen--) *out_dst++ = *out_src++;
			}
#else
			while (mlen--) *out_dst++ = *out_src++;
#endif
		}
	}

	return itt;
}

STATIC i32
compress_calculate_block_type(const u32 frequencies[SYMBOL_COUNT],
			      const u32 book_frequencies[MAX_BOOK_CODES],
			      const CodeLength code_lengths[SYMBOL_COUNT],
			      const CodeLength book[MAX_BOOK_CODES], u32 len) {
	u32 sum = 0;
	for (u32 i = 0; i < SYMBOL_COUNT; i++) {
		sum += frequencies[i] * code_lengths[i].length;
		if (i >= MATCH_OFFSET)
			sum += frequencies[i] *
			       (DIST_EXTRA_BITS(i - MATCH_OFFSET) +
				LEN_EXTRA_BITS(i - MATCH_OFFSET));
	}
	sum += MAX_BOOK_CODES * 3;
	for (u32 i = 0; i < MAX_BOOK_CODES; i++) {
		sum += book_frequencies[i] * book[i].length;
		if (i == REPEAT_VALUE_INDEX) sum += book_frequencies[i] * 2;
		if (i == REPEAT_ZERO_LONG_INDEX) sum += book_frequencies[i] * 7;
		if (i == REPEAT_ZERO_SHORT_INDEX)
			sum += book_frequencies[i] * 3;
	}
	sum += 7 + 64 + 64;
	sum >>= 3;
	return sum > len;
}

STATIC i32 compress_write_raw(const u8 *in, u32 len, u8 *out) {
	u32 value;
	if (!len) {
		out[0] = 0x0;
		out[1] = 0x0;
		out[2] = 0x80;
		return 3;
	}
	value = len | 0x00800000;
	fastmemcpy(out, &value, 3);
	fastmemcpy(out + 3, in, len);
	return len + 3;
}

STATIC i32 compress_read_raw(const u8 *in, u32 len, u8 *out, u32 capacity) {
	u32 block_len;
	u8 bytes[4];

	if (len < 3) {
		errno = EOVERFLOW;
		return -1;
	}
	if (len == 3) {
		if (in[0] != 0x0 || in[1] != 0 || in[2] != 0x80) {
			errno = EOVERFLOW;
			return -1;
		}
		return 0;
	}
	bytes[0] = in[0];
	bytes[1] = in[1];
	bytes[2] = in[2] & ~0x80;
	bytes[3] = 0;
	block_len = (*(u32 *)bytes);
	if (block_len > capacity) {
		errno = EOVERFLOW;
		return -1;
	}
	if (len < block_len + 3) {
		errno = EOVERFLOW;
		return -1;
	}

	fastmemcpy(out, in + 3, block_len);
	return block_len;
}

PUBLIC u64 compress_bound(u64 source_len) { return source_len + 3; }

PUBLIC i32 compress_block(const u8 *in, u32 len, u8 *out, u32 capacity) {
	u16 match_array[MAX_COMPRESS_LEN + 2] = {0};
	u32 frequencies[SYMBOL_COUNT] = {0};
	CodeLength code_lengths[SYMBOL_COUNT] = {0};
	u32 book_frequencies[MAX_BOOK_CODES] = {0};
	CodeLength book[MAX_BOOK_CODES] = {0};

#if TEST == 1
	if (_debug_compress_fail) return -1;
#endif /* TEST */

	if (in == NULL || out == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (capacity < compress_bound(len) || len > MAX_COMPRESS_LEN) {
		errno = EINVAL;
		return -1;
	}

	u32 out_bit_offset =
	    find_matches(in, len, match_array, frequencies, out);
	compress_calculate_lengths(frequencies, code_lengths, SYMBOL_COUNT,
				   MAX_CODE_LENGTH);
	compress_calculate_codes(code_lengths, SYMBOL_COUNT);
	compress_build_code_book(code_lengths, book, book_frequencies);

	if (compress_calculate_block_type(frequencies, book_frequencies,
					  code_lengths, book, len)) {
		return compress_write_raw(in, len, out);
	} else {
		return compress_write(code_lengths, book, match_array, out,
				      out_bit_offset);
	}
}

PUBLIC i32 decompress_block(const u8 *in, u32 len, u8 *out, u32 capacity) {
#if TEST == 1
	if (_debug_compress_fail) return -1;
#endif /* TEST */

	if (in == NULL || out == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (len < 3) {
		errno = EOVERFLOW;
		return -1;
	}
	if ((in[2] & 0x80) != 0) {
		return compress_read_raw(in, len, out, capacity);
	} else {
		return compress_read_block(in, len, out, capacity);
	}
}

