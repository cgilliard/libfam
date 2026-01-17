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

#include <libfam/compress.h>
#include <libfam/flags.h>
#include <libfam/format.h>
#include <libfam/limits.h>
#include <libfam/linux.h>
#include <libfam/main.h>
#include <libfam/version.h>

#define CZIP_VERSION 0
#define CZIP_MAGIC 0xCC337711
#define MAX_PATH 1024

typedef struct {
	bool decompress;
	bool console;
	bool version;
	bool help;
	bool keep;
	const u8 *file;
	i32 return_value;
} CzipConfig;

typedef struct {
	u64 file_size;
	u64 mtime;
	u64 atime;
	u16 permissions;
	u16 czip_version;
	const u8 *file;
} CzipFileHeader;

static CzipConfig parse_argv(i32 argc, u8 **argv) {
	CzipConfig ret = {0};
	i32 i;
	for (i = 1; i < argc; i++) {
		u8 *arg = argv[i];
		if (*arg == '-') {
			arg++;
			if (*arg == '-') {
				arg++;
				if (!strcmp(arg, "decompress")) {
					ret.decompress = true;
				} else if (!strcmp(arg, "console")) {
					ret.console = true;
				} else if (!strcmp(arg, "version")) {
					ret.version = true;
					return ret;
				} else if (!strcmp(arg, "help")) {
					ret.help = true;
					return ret;
				} else if (!strcmp(arg, "keep")) {
					ret.keep = true;
					return ret;
				} else {
					println("Illegal option: '{}'",
						argv[i]);
					ret.help = true;
					ret.file = "";
					ret.return_value = -1;
					return ret;
				}
			} else if (*arg == '\0') {
				ret.file = "";
			} else {
				u8 ch;
				while ((ch = *arg++)) {
					if (ch == 'd')
						ret.decompress = true;
					else if (ch == 'c')
						ret.console = true;
					else if (ch == 'h')
						ret.help = true;
					else if (ch == 'v')
						ret.version = true;
					else if (ch == 'k')
						ret.keep = true;
					else {
						println("Illegal option: '{c}'",
							ch);
						ret.help = true;
						ret.return_value = -1;
						ret.file = "";
						return ret;
					}
				}
			}
		} else {
			if (ret.file) {
				println("Error: Multiple files specified!");
				ret.help = true;
				ret.return_value = -1;
				return ret;
			}
			ret.file = arg;
		}
	}
	return ret;
}

static void decompress(CzipConfig *config) {
	i32 res;
	u32 magic, mode;
	u8 version;
	i32 infd, outfd;
	u64 atime, mtime;
	u8 outpath[MAX_PATH] = {0};
	bool use_stdin = !config->file;

	if (!use_stdin && !exists(config->file)) {
		println("Specified file '{}' does not exist.", config->file);
		exit_group(-1);
	}

	if (use_stdin)
		infd = 0;
	else
		infd = open(config->file, O_RDONLY, 0);
	if (infd < 0) {
		println("Could not open specified file '{}'", config->file);
		exit_group(-1);
	}

	if (pread(infd, &magic, sizeof(u32), 0) != sizeof(u32)) {
		println("Magic read error.");
		exit_group(-1);
	}
	if (pread(infd, &version, sizeof(u8), 4) != sizeof(u8)) {
		println("Version read error.");
		exit_group(-1);
	}

	if (pread(infd, &atime, sizeof(atime), 5) != sizeof(atime)) {
		println("Atime read error.");
		exit_group(-1);
	}

	if (pread(infd, &mtime, sizeof(mtime), 13) != sizeof(mtime)) {
		println("Mtime read error.");
		exit_group(-1);
	}

	if (pread(infd, &mode, sizeof(mode), 21) != sizeof(mode)) {
		println("Mode read error.");
		exit_group(-1);
	}

	u8 flen;
	if (pread(infd, &flen, sizeof(flen), 25) != sizeof(flen)) {
		println("flen read error.");
		exit_group(-1);
	}

	if (magic != CZIP_MAGIC || version != CZIP_VERSION) {
		println("Magic error! {}/{} (expected {}/{}", magic, version,
			CZIP_MAGIC, CZIP_VERSION);
		exit_group(-1);
	}

	if (pread(infd, outpath, flen, 26) != flen) {
		println("file name read error.");
		exit_group(-1);
	}

	outfd = config->console ? 1 : open(outpath, O_CREAT | O_RDWR, 600);

	if (config->console || use_stdin) {
		res = decompress_stream(infd, 26 + flen, outfd, 0);
	} else
		res = decompress_file(infd, 26 + flen, outfd, 0);

	if (!use_stdin) close(infd);
	if (!config->console) {
		if (!mode) mode = 0600;
		if (fchmod(outfd, mode) < 0) {
			println("Could not set file permissions.");
			exit_group(-1);
		}

		if (atime || mtime) {
			struct timeval ts[2] = {0};
			ts[0].tv_sec = atime;
			ts[1].tv_sec = mtime;
			if (utimesat(outfd, NULL, ts, 0) < 0) {
				println("Could not set file times.");
				exit_group(-1);
			}
		}

		close(outfd);
	}
	if (res < 0) println("Warning: decompression failed!");
	if (res >= 0 && !config->keep && !config->console && !use_stdin)
		unlink(config->file);
}

static void compress(CzipConfig *config) {
	u8 vval;
	u32 wval;
	i32 infd, outfd, res;
	u8 outpath[MAX_PATH] = {0};
	bool use_stdin = !config->file;

	if (!use_stdin && strlen(config->file) >= MAX_PATH - 4) {
		println("File name too long!");
		exit_group(-1);
	}

	if (!use_stdin && !exists(config->file)) {
		println("Specified file '{}' does not exist.", config->file);
		exit_group(-1);
	}

	if (use_stdin)
		infd = 0;
	else
		infd = open(config->file, O_RDONLY, 0);

	if (infd < 0) {
		println("Could not open specified file '{}'", config->file);
		exit_group(-1);
	}

	if (config->console || use_stdin)
		outfd = 1;
	else {
		strcpy(outpath, config->file);
		strcat(outpath, ".cz");

		outfd = open(outpath, O_CREAT | O_RDWR, 0600);
		if (outfd < 0) {
			println("Could not open output file '{}'", outpath);
			exit_group(-1);
		}
	}

	wval = CZIP_MAGIC;
	vval = CZIP_VERSION;
	struct statx stx = {0};
	if (!use_stdin && fstatx(infd, &stx) < 0) {
		println("Could not stat input file.");
		exit_group(-1);
	}

	if (pwrite(outfd, &wval, sizeof(u32), 0) != sizeof(u32)) {
		println("Magic write error.");
		exit_group(-1);
	}
	if (pwrite(outfd, &vval, sizeof(u8), 4) != sizeof(u8)) {
		println("Version write error.");
		exit_group(-1);
	}
	if (pwrite(outfd, &stx.stx_atime, sizeof(u64), 5) != sizeof(u64)) {
		println("attime write error.");
		exit_group(-1);
	}

	if (pwrite(outfd, &stx.stx_mtime, sizeof(u64), 13) != sizeof(u64)) {
		println("mttime write error.");
		exit_group(-1);
	}

	if (pwrite(outfd, &stx.stx_mode, sizeof(u32), 21) != sizeof(u32)) {
		println("stmode write error.");
		exit_group(-1);
	}

	u8 flen;
	u64 flen64 =
	    config->file ? strlen(config->file) : strlen("default.txt");
	if (flen64 > U8_MAX) {
		println("file name '{}' is too long. Max 255.", config->file);
		exit_group(-1);
	}
	flen = flen64;

	if (pwrite(outfd, &flen, sizeof(u8), 25) != sizeof(u8)) {
		println("flen write error.");
		exit_group(-1);
	}
	if (pwrite(outfd,
		   (const void *)config->file != (const void *)NULL
		       ? (void *)config->file
		       : "default.txt",
		   flen, 26) != flen) {
		println("file name write error.");
		exit_group(-1);
	}

	if (config->console || use_stdin) {
		res = compress_stream(infd, 0, outfd, 26 + flen);
	} else {
		res = compress_file(infd, 0, outfd, 26 + flen);
	}

	if (!use_stdin) close(infd);
	if (!config->console) close(outfd);

	if (res < 0) println("Warning: compression failed!");
	if (res >= 0 && !config->keep && !config->console) unlink(config->file);
}

i32 main(i32 argc, u8 **argv, u8 **envp) {
	CzipConfig config = parse_argv(argc, argv);

	if (config.version) {
		println("czip {}", LIBFAM_VERSION);
	} else if (config.help) {
		println("Usage: czip [OPTION]... [FILE]...");
		println(
		    "-c, --console       write to standard output, "
		    "keep files "
		    "unchanged");
		println("-d, --decompress    decompress");
		println("-h, --help          print this message");
		println("-v, --version       print version");
		println("-k, --keep          keep original file");
		println(
		    "\nNote: if no file is specified stdin will be "
		    "used as "
		    "the "
		    "input file.");
		return config.return_value;
	} else if (config.decompress) {
		decompress(&config);
	} else {
		compress(&config);
	}

	return 0;
}
