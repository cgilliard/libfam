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

#ifndef _COLORS_H
#define _COLORS_H

#include <libfam/types.h>

const u8 *get_dimmed(void);
#define DIMMED get_dimmed()

const u8 *get_red(void);
#define RED get_red()

const u8 *get_bright_red(void);
#define BRIGHT_RED get_bright_red()

const u8 *get_green(void);
#define GREEN get_green()

const u8 *get_yellow(void);
#define YELLOW get_yellow()

const u8 *get_cyan(void);
#define CYAN get_cyan()

const u8 *get_magenta(void);
#define MAGENTA get_magenta()

const u8 *get_blue(void);
#define BLUE get_blue()

const u8 *get_reset(void);
#define RESET get_reset()

#endif /* _COLORS_H */
