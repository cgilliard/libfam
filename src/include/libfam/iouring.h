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

#ifndef _IOURING_H
#define _IOURING_H

#include <libfam/types.h>

struct io_cqring_offsets {
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 ring_entries;
	u32 overflow;
	u32 cqes;
	u32 flags;
	u32 resv1;
	u64 user_addr;
};

struct io_sqring_offsets {
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 ring_entries;
	u32 flags;
	u32 dropped;
	u32 array;
	u32 resv1;
	u64 user_addr;
};

struct io_uring_params {
	u32 sq_entries;
	u32 cq_entries;
	u32 flags;
	u32 sq_thread_cpu;
	u32 sq_thread_idle;
	u32 features;
	u32 wq_fd;
	u32 resv[3];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};

struct io_uring_rsrc_update2 {
	u32 offset;
	u32 resv;
	u64 data;
	u64 tags;
	u32 nr;
	u32 resv2;
};

struct io_uring_cqe {
	u64 user_data;
	i32 res;
	u32 flags;
	u64 big_cqe[];
};

struct io_uring_sqe {
	u8 opcode;
	u8 flags;
	u16 ioprio;
	i32 fd;
	union {
		u64 off;
		u64 addr2;
		struct {
			u32 cmd_op;
			u32 __pad1;
		};
	};
	union {
		u64 addr;
		u64 splice_off_in;
		struct {
			u32 level;
			u32 optname;
		};
	};
	u32 len;
	union {
		u32 rw_flags;
		u32 fsync_flags;
		u16 poll_events;
		u32 poll32_events;
		u32 sync_range_flags;
		u32 msg_flags;
		u32 timeout_flags;
		u32 accept_flags;
		u32 cancel_flags;
		u32 open_flags;
		u32 statx_flags;
		u32 fadvise_advice;
		u32 splice_flags;
		u32 rename_flags;
		u32 unlink_flags;
		u32 hardlink_flags;
		u32 xattr_flags;
		u32 msg_ring_flags;
		u32 uring_cmd_flags;
		u32 waitid_flags;
		u32 futex_flags;
		u32 install_fd_flags;
	};
	u64 user_data;
	union {
		u16 buf_index;
		u16 buf_group;
	} __attribute__((packed));
	u16 personality;
	union {
		i32 splice_fd_in;
		u32 file_index;
		u32 optlen;
		struct {
			u16 addr_len;
			u16 __pad3[1];
		};
	};
	union {
		struct {
			u64 addr3;
			u64 __pad2[1];
		};
		u64 optval;
		u8 cmd[0];
	};
};

#define IORING_SETUP_SQPOLL (1U << 1)
#define IORING_RECVSEND_POLL_FIRST (1U << 0)
#define IORING_RECV_MULTISHOT (1U << 1)
#define IORING_RECVSEND_FIXED_BUF (1U << 2)
#define IORING_SEND_ZC_REPORT_USAGE (1U << 3)
#define IORING_RECVSEND_BUNDLE (1U << 4)
#define IORING_SEND_VECTORIZED (1U << 5)

enum io_uring_op {
	IORING_OP_NOP,
	IORING_OP_READV,
	IORING_OP_WRITEV,
	IORING_OP_FSYNC,
	IORING_OP_READ_FIXED,
	IORING_OP_WRITE_FIXED,
	IORING_OP_POLL_ADD,
	IORING_OP_POLL_REMOVE,
	IORING_OP_SYNC_FILE_RANGE,
	IORING_OP_SENDMSG,
	IORING_OP_RECVMSG,
	IORING_OP_TIMEOUT,
	IORING_OP_TIMEOUT_REMOVE,
	IORING_OP_ACCEPT,
	IORING_OP_ASYNC_CANCEL,
	IORING_OP_LINK_TIMEOUT,
	IORING_OP_CONNECT,
	IORING_OP_FALLOCATE,
	IORING_OP_OPENAT,
	IORING_OP_CLOSE,
	IORING_OP_FILES_UPDATE,
	IORING_OP_STATX,
	IORING_OP_READ,
	IORING_OP_WRITE,
	IORING_OP_FADVISE,
	IORING_OP_MADVISE,
	IORING_OP_SEND,
	IORING_OP_RECV,
	IORING_OP_OPENAT2,
	IORING_OP_EPOLL_CTL,
	IORING_OP_SPLICE,
	IORING_OP_PROVIDE_BUFFERS,
	IORING_OP_REMOVE_BUFFERS,
	IORING_OP_TEE,
	IORING_OP_SHUTDOWN,
	IORING_OP_RENAMEAT,
	IORING_OP_UNLINKAT,
	IORING_OP_MKDIRAT,
	IORING_OP_SYMLINKAT,
	IORING_OP_LINKAT,
	IORING_OP_MSG_RING,
	IORING_OP_FSETXATTR,
	IORING_OP_SETXATTR,
	IORING_OP_FGETXATTR,
	IORING_OP_GETXATTR,
	IORING_OP_SOCKET,
	IORING_OP_URING_CMD,
	IORING_OP_SEND_ZC,
	IORING_OP_SENDMSG_ZC,
	IORING_OP_READ_MULTISHOT,
	IORING_OP_WAITID,
	IORING_OP_FUTEX_WAIT,
	IORING_OP_FUTEX_WAKE,
	IORING_OP_FUTEX_WAITV,
	IORING_OP_FIXED_FD_INSTALL,
	IORING_OP_FTRUNCATE,
	IORING_OP_BIND,
	IORING_OP_LISTEN,
	IORING_OP_RECV_ZC,
	IORING_OP_EPOLL_WAIT,
	IORING_OP_READV_FIXED,
	IORING_OP_WRITEV_FIXED,
	IORING_OP_PIPE,
	IORING_OP_NOP128,
	IORING_OP_URING_CMD128,
	IORING_OP_LAST,
};

enum {
	IOSQE_FIXED_FILE_BIT,
	IOSQE_IO_DRAIN_BIT,
	IOSQE_IO_LINK_BIT,
	IOSQE_IO_HARDLINK_BIT,
	IOSQE_ASYNC_BIT,
	IOSQE_BUFFER_SELECT_BIT,
	IOSQE_CQE_SKIP_SUCCESS_BIT,
};

#define IOSQE_FIXED_FILE (1U << IOSQE_FIXED_FILE_BIT)
#define IOSQE_IO_DRAIN (1U << IOSQE_IO_DRAIN_BIT)
#define IOSQE_IO_LINK (1U << IOSQE_IO_LINK_BIT)
#define IOSQE_IO_HARDLINK (1U << IOSQE_IO_HARDLINK_BIT)
#define IOSQE_ASYNC (1U << IOSQE_ASYNC_BIT)
#define IOSQE_BUFFER_SELECT (1U << IOSQE_BUFFER_SELECT_BIT)
#define IOSQE_CQE_SKIP_SUCCESS (1U << IOSQE_CQE_SKIP_SUCCESS_BIT)

#define IORING_FSYNC_DATASYNC (1U << 0)

#define IORING_OFF_SQ_RING 0ULL
#define IORING_OFF_CQ_RING 0x8000000ULL
#define IORING_OFF_SQES 0x10000000ULL
#define IORING_OFF_PBUF_RING 0x80000000ULL
#define IORING_OFF_PBUF_SHIFT 16
#define IORING_OFF_MMAP_MASK 0xf8000000ULL

#define IORING_ENTER_GETEVENTS (1U << 0)
#define IORING_ENTER_SQ_WAKEUP (1U << 1)
#define IORING_ENTER_SQ_WAIT (1U << 2)
#define IORING_ENTER_EXT_ARG (1U << 3)
#define IORING_ENTER_REGISTERED_RING (1U << 4)

enum {
	IORING_REGISTER_BUFFERS = 0,
	IORING_UNREGISTER_BUFFERS = 1,
	IORING_REGISTER_FILES = 2,
	IORING_UNREGISTER_FILES = 3,
	IORING_REGISTER_EVENTFD = 4,
	IORING_UNREGISTER_EVENTFD = 5,
	IORING_REGISTER_FILES_UPDATE = 6,
	IORING_REGISTER_EVENTFD_ASYNC = 7,
	IORING_REGISTER_PROBE = 8,
	IORING_REGISTER_PERSONALITY = 9,
	IORING_UNREGISTER_PERSONALITY = 10,
	IORING_REGISTER_RESTRICTIONS = 11,
	IORING_REGISTER_ENABLE_RINGS = 12,
	IORING_REGISTER_FILES2 = 13,
	IORING_REGISTER_FILES_UPDATE2 = 14,
	IORING_REGISTER_BUFFERS2 = 15,
	IORING_REGISTER_BUFFERS_UPDATE = 16,
	IORING_REGISTER_IOWQ_AFF = 17,
	IORING_UNREGISTER_IOWQ_AFF = 18,
	IORING_REGISTER_IOWQ_MAX_WORKERS = 19,
	IORING_REGISTER_RING_FDS = 20,
	IORING_UNREGISTER_RING_FDS = 21,
	IORING_REGISTER_PBUF_RING = 22,
	IORING_UNREGISTER_PBUF_RING = 23,
	IORING_REGISTER_SYNC_CANCEL = 24,
	IORING_REGISTER_FILE_ALLOC_RANGE = 25,
	IORING_REGISTER_PBUF_STATUS = 26,
	IORING_REGISTER_LAST,
	IORING_REGISTER_USE_REGISTERED_RING = 1U << 31
};

#define IORING_TIMEOUT_ABS (1U << 0)
#define IORING_TIMEOUT_UPDATE (1U << 1)
#define IORING_TIMEOUT_BOOTTIME (1U << 2)
#define IORING_TIMEOUT_REALTIME (1U << 3)
#define IORING_LINK_TIMEOUT_UPDATE (1U << 4)
#define IORING_TIMEOUT_ETIME_SUCCESS (1U << 5)
#define IORING_TIMEOUT_MULTISHOT (1U << 6)
#define IORING_TIMEOUT_CLOCK_MASK \
	(IORING_TIMEOUT_BOOTTIME | IORING_TIMEOUT_REALTIME)
#define IORING_TIMEOUT_UPDATE_MASK \
	(IORING_TIMEOUT_UPDATE | IORING_LINK_TIMEOUT_UPDATE)

#endif /* _IOURING_H */
