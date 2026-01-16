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

#include <libfam/env.h>
#include <libfam/types.h>
#include <libfam/utils.h>

i32 no_color(void) { return getenv("NO_COLOR") != NULL; }
const u8 *get_dimmed(void) { return no_color() ? "" : "\x1b[2m"; }
const u8 *get_red(void) { return no_color() ? "" : "\x1b[31m"; }
const u8 *get_bright_red(void) { return no_color() ? "" : "\x1b[91m"; }
const u8 *get_green(void) { return no_color() ? "" : "\x1b[32m"; }
const u8 *get_yellow(void) { return no_color() ? "" : "\x1b[33m"; }
const u8 *get_cyan(void) { return no_color() ? "" : "\x1b[36m"; }
const u8 *get_magenta(void) { return no_color() ? "" : "\x1b[35m"; }
const u8 *get_blue(void) { return no_color() ? "" : "\x1b[34m"; }
const u8 *get_reset(void) { return no_color() ? "" : "\x1b[0m"; }
