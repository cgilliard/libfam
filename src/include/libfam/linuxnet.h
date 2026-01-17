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

#ifndef _LINUXNET_H
#define _LINUXNET_H

#include <libfam/types.h>

#define AF_INET 2
#define SOCK_STREAM 1
#define SOL_SOCKET 1
#define SO_REUSEADDR 2
#define INADDR_ANY 0x00000000U

struct sockaddr {
	u16 sa_family;
	char sa_data[14];
};

struct in_addr {
	u32 s_addr;
};

struct sockaddr_in {
	u16 sin_family;
	u16 sin_port;
	struct in_addr sin_addr;
	u8 sin_zero[8];
};

static inline u16 htons(u16 hostshort) {
	return (hostshort << 8) | (hostshort >> 8);
}

static inline u32 htonl(u32 hostlong) {
	return ((hostlong & 0xFF000000U) >> 24) |
	       ((hostlong & 0x00FF0000U) >> 8) |
	       ((hostlong & 0x0000FF00U) << 8) |
	       ((hostlong & 0x000000FFU) << 24);
}

#define ntohs(x) htons(x)

#endif /* _LINUXNET_H */
