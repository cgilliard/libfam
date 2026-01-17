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

#ifndef _FLAGS_H
#define _FLAGS_H

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

#endif /* _FLAGS_H */
