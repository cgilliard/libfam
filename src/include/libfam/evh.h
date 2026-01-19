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

#ifndef _EVH_H
#define _EVH_H

#include <libfam/async.h>
#include <libfam/types.h>

#define EVH_PACKET_SIZE 1400

typedef struct {
	u32 queue_depth;
	u16 port;
	u32 addr;
	AsyncCallback callback;
} EvhConfig;

typedef struct Evh Evh;

i32 evh_init(Evh **evh, EvhConfig *config);
i32 evh_start(Evh *evh);
i32 evh_stop(Evh *evh);
void evh_destroy(Evh *evh);
u16 evh_port(Evh *evh);
const u8 *evh_get_packet(Evh *evh);
const struct sockaddr_in *evh_get_src_addr(Evh *evh);
i32 evh_schedule(Evh *evh, const struct io_uring_sqe *events, u32 count);

#endif /* _EVH_H */
