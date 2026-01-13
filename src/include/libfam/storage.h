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

#ifndef _STORAGE_H
#define _STORAGE_H

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif /* PAGE_SIZE */

#include <libfam/types.h>

typedef struct Storage Storage;
typedef void (*StorageReadOnComplete)(const u8 buffer[PAGE_SIZE], u64 id);
typedef void (*StorageFlushOnComplete)(u64 id);

Storage *storage_init(const u8 *path, u64 cache_sector_count, u64 hash_buckets,
		      u64 queue_size);
i32 storage_write(Storage *s, const u8 buffer[PAGE_SIZE], u64 sector);
i32 storage_read(Storage *s, u64 sector, u64 id,
		 const StorageReadOnComplete *callback);
i32 storage_flush(Storage *s, u64 id, const StorageFlushOnComplete *callback);
void storage_destroy(Storage *s);

#endif /* _STORAGE_H */
