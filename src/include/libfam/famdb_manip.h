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

#ifndef _FAMDB_MANIP_H
#define _FAMDB_MANIP_H

#include <libfam/format.h>
#include <libfam/types.h>

#define PAGE_TYPE_INTERNAL_FLAG (0x1 << 0)

/*
 * Layout:
 * [2 bytes flags - PAGE_TYPE_INTERNAL_FLAG]
 * [2 bytes elements]
 * [2 bytes total bytes]
 * [8 byte next pointer - only releavant for leaf nodes]
 * [variable byte offset array - 2 byte values]
 * [variable byte data array - see format below]
 * [Tag - 16 bytes]
 *
 * data layout (internal):
 * [8 byte pointer][variable byte key - length inferrered from offsets][8 byte
 * pointer]...
 *
 * data layout (leaf):
 * [4 byte key/value len][9 bit (up to 511) key length][7 bits flags]
 *
 * Current flags:
 * 1.) none - regular inline in block (key/value)
 * 2.) first bit - external pointer (then the next 8 bytes point to block for
 * this key/value)
 */

#define PAGE_IS_INTERNAL(page) ((page[0] & PAGE_TYPE_INTERNAL_FLAG))
#define PAGE_IS_LEAF(page) (!(page[0] & PAGE_TYPE_INTERNAL_FLAG))
#define PAGE_ELEMENTS(page) (((u16 *)page)[1])
#define PAGE_TOTAL_BYTES(page) (((u16 *)page)[2])
#define PAGE_OFFSET_OF(page, elem) (((u16 *)page)[elem + 3])
#define LEAF_ENTRY_LEN(page, elem) \
	(((u32 *)(page + PAGE_OFFSET_OF(page, elem)))[0])
#define LEAF_KEY_LEN(page, elem) \
	(((u16 *)(page + PAGE_OFFSET_OF(page, elem) + sizeof(u32)))[0])
#define LEAF_VALUE_LEN(page, elem) \
	(LEAF_ENTRY_LEN(page, elem) - LEAF_KEY_LEN(page, elem))
#define LEAF_READ_KEY(page, elem) \
	(page + PAGE_OFFSET_OF(page, elem) + sizeof(u32) + sizeof(u16))
#define LEAF_READ_VALUE(page, elem)                                      \
	(page + PAGE_OFFSET_OF(page, elem) + sizeof(u32) + sizeof(u16) + \
	 LEAF_KEY_LEN(page, elem))
#define LEAF_COMPARE_KEYS(page, elem, key, key_len)                       \
	({                                                                \
		u16 elem_key_off = PAGE_OFFSET_OF(page, elem);            \
		u16 elem_key_len = LEAF_KEY_LEN(page, elem);              \
		u16 min_len = min(key_len, elem_key_len);                 \
		i32 cmp = __builtin_memcmp(                               \
		    key, page + elem_key_off + sizeof(u32) + sizeof(u16), \
		    min_len);                                             \
		cmp != 0		 ? cmp                            \
		: key_len > elem_key_len ? 1                              \
		: key_len < elem_key_len ? -1                             \
					 : 0;                             \
	})
#define LEAF_FIND_INDEX(page, key, key_len)                               \
	({                                                                \
		u16 min = 0, max = PAGE_ELEMENTS(page), mid;              \
		i32 cmp;                                                  \
		while (min < max) {                                       \
			mid = min + ((max - min) >> 1);                   \
			cmp = LEAF_COMPARE_KEYS(page, mid, key, key_len); \
			if (cmp == 0) {                                   \
				min = mid;                                \
				break;                                    \
			} else if (cmp < 0)                               \
				max = mid;                                \
			else                                              \
				min = mid + 1;                            \
		}                                                         \
		min;                                                      \
	})
#define LEAF_INSERT_AT(page, data_off, elem, key, key_len, value, value_len)   \
	({                                                                     \
		u16 _offset__ = PAGE_OFFSET_OF(page, elem);                    \
		if (_offset__ == 0) {                                          \
			_offset__ = PAGE_TOTAL_BYTES(page) + data_off;         \
			((u16 *)page)[elem + 3] = _offset__;                   \
		}                                                              \
		u16 _nentry_len__ =                                            \
		    key_len + value_len + sizeof(u16) + sizeof(u32);           \
		if (PAGE_ELEMENTS(page) > elem)                                \
			__builtin_memmove(                                     \
			    page + _offset__ + _nentry_len__,                  \
			    page + _offset__,                                  \
			    data_off + PAGE_TOTAL_BYTES(page) - _offset__);    \
		((u16 *)page)[2] += _nentry_len__;                             \
		((u16 *)page)[1]++;                                            \
		((u32 *)(page + _offset__))[0] = key_len + value_len;          \
		((u16 *)(page + _offset__ + sizeof(u32)))[0] = key_len;        \
		__builtin_memcpy(page + _offset__ + sizeof(u32) + sizeof(u16), \
				 key, key_len);                                \
		__builtin_memcpy(                                              \
		    page + _offset__ + sizeof(u32) + sizeof(u16) + key_len,    \
		    value, value_len);                                         \
		for (u32 i = elem + 1; i < PAGE_ELEMENTS(page); i++)           \
			((u16 *)page)[i + 3] = ((u16 *)page)[i + 2] +          \
					       LEAF_ENTRY_LEN(page, i - 1) +   \
					       sizeof(u16) + sizeof(u32);      \
	})
#define LEAF_INSERT(page, data_off, key, key_len, value, value_len)     \
	({                                                              \
		u16 index = LEAF_FIND_INDEX(page, (key), (key_len));    \
		LEAF_INSERT_AT(page, data_off, index, (key), (key_len), \
			       (value), (value_len));                   \
	})

#endif /* _FAMDB_MANIP_H */
