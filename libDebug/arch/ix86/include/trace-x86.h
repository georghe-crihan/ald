/*
 * libDebug
 *
 * Copyright (C) 2000 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: trace-x86.h,v 1.3 2004/09/11 05:17:15 pa33 Exp $
 */

#ifndef INCLUDED_trace_x86_h
#define INCLUDED_trace_x86_h

#ifndef INCLUDED_libDebug_h
#include "libDebug.h"
#define INCLUDED_libDebug_h
#endif

/*
 * Opcode for INT 3 (breakpoint trap) instruction
 */
#define BRKPT_INSN    0xCC

#if defined(OS_BSD) /* FreeBSD, OpenBSD, NetBSD */

/*
 * Continuation address
 */
#define CONTADDR   ((caddr_t) 1)

#define PtraceRead(pid, addr, data) \
  ptrace(PT_READ_D, (pid), (caddr_t) (addr), (data))

#define PtraceWrite(pid, addr, data) \
  ptrace(PT_WRITE_D, (pid), (caddr_t) (addr), (data))

#elif defined(OS_LINUX)

#define CONTADDR   (0)

#define PtraceRead(pid, addr, data) \
  ptrace(PT_READ_D, (pid), (addr), (data))

#define PtraceWrite(pid, addr, data) \
  ptrace(PT_WRITE_D, (pid), (addr), (data))

#else

# error No supported operating system found

#endif

/*
 * Prototypes
 */

struct debugWorkspace;

int x86execDebug(struct debugWorkspace *ws);
int x86stepIntoDebug(struct debugWorkspace *ws, int num, int *data);
int x86stepOverDebug(struct debugWorkspace *ws, int num, int *data);
int x86continueDebug(struct debugWorkspace *ws, int *data);
int x86attachDebug(struct debugWorkspace *ws, int pid);
int x86detachDebug(struct debugWorkspace *ws);
int x86killDebug(struct debugWorkspace *ws);
int x86saveBreakpoint(struct debugWorkspace *ws, struct Breakpoint *bptr);
int x86enableBreakpoint(struct debugWorkspace *ws, struct Breakpoint *bptr);
int x86disableBreakpoint(struct debugWorkspace *ws, struct Breakpoint *bptr);
long x86dumpMemoryDebug(struct debugWorkspace *ws, unsigned char **buf,
                        unsigned long start, unsigned long bytes);
int x86setMemoryDebug(struct debugWorkspace *ws, unsigned long address,
                      unsigned long value);

#endif /* INCLUDED_trace_x86_h */
