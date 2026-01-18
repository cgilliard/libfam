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

#include <libfam/format.h>
#include <libfam/server.h>
#include <libfam/test.h>

Test(server) {
	i32 res;
	Server *s = NULL;
	ServerConfig config = {.port = 0, .async_queue_depth = 128};
	ASSERT(!server_init(&s, &config), "server_init");
	u16 port = server_port(s);
	println("port={}", port);
	ASSERT(port, "server_port");
	i32 pid = fork();
	ASSERT(pid >= 0, "fork");

	if (!pid) {
		ASSERT(!server_start(s), "server_start");
		exit_group(0);
	}

	struct sockaddr_in addr = {.sin_family = AF_INET,
				   .sin_port = htons(port),
				   .sin_addr = {htonl(INADDR_ANY)}};
	u64 addrlen = sizeof(addr);

	i32 cfd = socket(AF_INET, SOCK_DGRAM, 0);
	ASSERT(cfd > 0, "socket");

	res = connect(cfd, (void *)&addr, addrlen);
	ASSERT(!res, "connect");

	ASSERT_EQ(pwrite(cfd, "abcd", 4, 0), 4, "pwrite");
	ASSERT_EQ(pwrite(cfd, "xyz123", 6, 0), 6, "pwrite2");

	usleep(1000);
	server_stop(s);
	server_destroy(s);
	close(cfd);
}
