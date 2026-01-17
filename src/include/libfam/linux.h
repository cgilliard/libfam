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

#ifndef _LINUX_H
#define _LINUX_H

#include <libfam/types.h>

#define STATX_BASIC_STATS 0x07ffU
#define AT_EMPTY_PATH 0x1000

struct statx_timestamp {
	i64 tv_sec;
	u32 tv_nsec;
	i32 __reserved;
};

struct statx {
	u32 stx_mask;
	u32 stx_blksize;
	u64 stx_attributes;
	u32 stx_nlink;
	u32 stx_uid;
	u32 stx_gid;
	u16 stx_mode;
	u16 __spare0[1];
	u64 stx_ino;
	u64 stx_size;
	u64 stx_blocks;
	u64 stx_attributes_mask;
	struct statx_timestamp stx_atime;
	struct statx_timestamp stx_btime;
	struct statx_timestamp stx_ctime;
	struct statx_timestamp stx_mtime;
	u32 stx_rdev_major;
	u32 stx_rdev_minor;
	u32 stx_dev_major;
	u32 stx_dev_minor;
	u64 stx_mnt_id;
	u32 stx_dio_mem_align;
	u32 stx_dio_offset_align;
	u64 __spare3[12];
};

#ifdef __x86_64__
struct stat {
	u64 st_dev;
	u64 st_ino;
	u64 st_nlink;
	u32 st_mode;
	u32 st_uid;
	u32 st_gid;
	u32 __pad0;
	u64 st_rdev;
	i64 st_size;
	i64 st_blksize;
	i64 st_blocks;
	u64 st_atime;
	u64 st_atimensec;
	u64 st_mtime;
	u64 st_mtimensec;
	u64 st_ctime;
	u64 st_ctimensec;
	i64 __unused[3];
};
#elif defined(__aarch64__)
struct stat {
	u64 st_dev;
	u64 st_ino;
	u32 st_mode;
	u32 st_nlink;
	u32 st_uid;
	u32 st_gid;
	u64 st_rdev;
	u64 __pad1;
	i64 st_size;
	i32 st_blksize;
	i32 __pad2;
	i64 st_blocks;
	i64 st_atime;
	u64 st_atime_nsec;
	i64 st_mtime;
	i64 st_mtime_nsec;
	i64 st_ctime;
	u64 st_ctime_nsec;
	u32 __unused4;
	u32 __unused5;
};
#endif /* __aarch64__ */

struct timespec {
	u64 tv_sec;
	u64 tv_nsec;
};

struct rt_sigaction {
	void (*k_sa_handler)(i32);
	u64 k_sa_flags;
	void (*k_sa_restorer)(void);
	u64 k_sa_mask;
};

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

struct open_how {
	u64 flags;
	u64 mode;
	u64 resolve;
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

struct iovec {
	void *iov_base;
	u64 iov_len;
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

struct timeval {
	u64 tv_sec;
	u64 tv_usec;
};

/* MMAP */
#define PROT_READ 0x01
#define PROT_WRITE 0x02
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FAILED ((void *)-1)

/* SIGNALS */
#define SIGHUP 1     /* Hangup */
#define SIGINT 2     /* Interrupt (Ctrl+C) */
#define SIGQUIT 3    /* Quit (Ctrl+\) */
#define SIGILL 4     /* Illegal instruction */
#define SIGTRAP 5    /* Trace/breakpoint trap */
#define SIGABRT 6    /* Abort */
#define SIGIOT 6     /* Alias for SIGABRT */
#define SIGBUS 7     /* Bus error */
#define SIGFPE 8     /* Floating-point exception */
#define SIGKILL 9    /* Kill (cannot be caught) */
#define SIGUSR1 10   /* User-defined signal 1 */
#define SIGSEGV 11   /* Segmentation fault */
#define SIGUSR2 12   /* User-defined signal 2 */
#define SIGPIPE 13   /* Broken pipe */
#define SIGALRM 14   /* Alarm clock */
#define SIGTERM 15   /* Termination */
#define SIGSTKFLT 16 /* Stack fault (rare) */
#define SIGCHLD 17   /* Child terminated/stopped */
#define SIGCONT 18   /* Continue */
#define SIGSTOP 19   /* Stop (cannot be caught) */
#define SIGTSTP 20   /* Terminal stop (Ctrl+Z) */
#define SIGTTIN 21   /* Background read from tty */
#define SIGTTOU 22   /* Background write to tty */
#define SIGURG 23    /* Urgent condition on socket */
#define SIGXCPU 24   /* CPU time limit exceeded */
#define SIGXFSZ 25   /* File size limit exceeded */
#define SIGVTALRM 26 /* Virtual timer expired */
#define SIGPROF 27   /* Profiling timer expired */
#define SIGWINCH 28  /* Window size changed */
#define SIGIO 29     /* I/O possible */
#define SIGPOLL 29   /* Alias for SIGIO */
#define SIGPWR 30    /* Power failure */
#define SIGSYS 31    /* Bad system call */
#define SIGUNUSED 31 /* Alias for SIGSYS */
#define SIGRTMIN 32  /* First real-time signal */
#define SIGRTMAX 64  /* Last real-time signal */

/* Clone flags for clone and clone3 */
#define CLONE_VM 0x00000100		/* Share memory */
#define CLONE_FS 0x00000200		/* Share filesystem info */
#define CLONE_FILES 0x00000400		/* Share file descriptors */
#define CLONE_SIGHAND 0x00000800	/* Share signal handlers */
#define CLONE_PIDFD 0x00001000		/* Return pidfd (clone3) */
#define CLONE_PTRACE 0x00002000		/* Continue ptrace */
#define CLONE_VFORK 0x00004000		/* vfork semantics */
#define CLONE_PARENT 0x00008000		/* Set parent to caller */
#define CLONE_THREAD 0x00010000		/* Same thread group */
#define CLONE_NEWNS 0x00020000		/* New mount namespace */
#define CLONE_SYSVSEM 0x00040000	/* Share System V semaphores */
#define CLONE_SETTLS 0x00080000		/* Set TLS */
#define CLONE_PARENT_SETTID 0x00100000	/* Store TID in parent */
#define CLONE_CHILD_CLEARTID 0x00200000 /* Clear TID on exit */
#define CLONE_DETACHED 0x00400000	/* Obsolete, ignored */
#define CLONE_UNTRACED 0x00800000	/* Don't trace child */
#define CLONE_CHILD_SETTID 0x01000000	/* Store TID in child */
#define CLONE_NEWCGROUP 0x02000000	/* New cgroup namespace */
#define CLONE_NEWUTS 0x04000000		/* New UTS namespace */
#define CLONE_NEWIPC 0x08000000		/* New IPC namespace */
#define CLONE_NEWUSER 0x10000000	/* New user namespace */
#define CLONE_NEWPID 0x20000000		/* New PID namespace */
#define CLONE_NEWNET 0x40000000		/* New network namespace */
#define CLONE_IO 0x80000000		/* Clone I/O context */

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID 3
#define CLOCK_MONOTONIC_RAW 4
#define CLOCK_REALTIME_COARSE 5
#define CLOCK_MONOTONIC_COARSE 6
#define CLOCK_BOOTTIME 7
#define CLOCK_REALTIME_ALARM 8
#define CLOCK_BOOTTIME_ALARM 9

#define AT_FDCWD -100

/* Open constants */
#define O_CREAT 0100
#define O_WRONLY 00000001
#define O_RDONLY 00000000
#define O_RDWR 02
#define O_EXCL 00000200
#define O_SYNC 04000000
#ifdef __aarch64__
#define O_DIRECT 0200000
#elif defined(__x86_64__)
#define O_DIRECT 00040000
#endif /* __x86_64__ */

/* SA_RESTORER - rt_sigaction */
#define SA_RESTORER 0x04000000

/* waitid consts */
#define P_PID 1
#define WEXITED 4

#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

#endif /* _LINUX_H */
