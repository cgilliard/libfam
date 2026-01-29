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

#ifndef _SIGNAL_H
#define _SIGNAL_H

struct rt_sigaction {
	void (*k_sa_handler)(i32);
	u64 k_sa_flags;
	void (*k_sa_restorer)(void);
	u64 k_sa_mask;
};

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

#define SA_RESTORER 0x04000000

#endif /* _SIGNAL_H */
