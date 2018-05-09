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
 * $Id: linux-x86.h,v 1.1.1.1 2004/04/26 00:41:04 pa33 Exp $
 */

#ifndef INCLUDED_linux_x86_h
#define INCLUDED_linux_x86_h

#ifndef INCLUDED_sys_ptrace_h
#include <sys/ptrace.h>
#define INCLUDED_sys_ptrace_h
#endif

#ifndef INCLUDED_libDebug_h
#include "libDebug.h"
#define INCLUDED_libDebug_h
#endif

#if !defined(PT_TRACE_ME) && defined(PTRACE_TRACEME)
#  define PT_TRACE_ME PTRACE_TRACEME
#endif

#if !defined(PT_READ_I) && defined(PTRACE_PEEKTEXT)
#  define PT_READ_I PTRACE_PEEKTEXT
#endif

#if !defined(PT_READ_D) && defined(PTRACE_PEEKDATA)
#  define PT_READ_D PTRACE_PEEKDATA
#endif

#if !defined(PT_READ_U) && defined(PTRACE_PEEKUSER)
#  define PT_READ_U PTRACE_PEEKUSER
#endif

#if !defined(PT_WRITE_I) && defined(PTRACE_POKETEXT)
#  define PT_WRITE_I PTRACE_POKETEXT
#endif

#if !defined(PT_WRITE_D) && defined(PTRACE_POKEDATA)
#  define PT_WRITE_D PTRACE_POKEDATA
#endif

#if !defined(PT_WRITE_U) && defined(PTRACE_POKEUSER)
#  define PT_WRITE_U PTRACE_POKEUSER
#endif

#if !defined(PT_CONTINUE) && defined(PTRACE_CONT)
#  define PT_CONTINUE PTRACE_CONT
#endif

#if !defined(PT_KILL) && defined(PTRACE_KILL)
#  define PT_KILL PTRACE_KILL
#endif

#if !defined(PT_STEP) && defined(PTRACE_SINGLESTEP)
#  define PT_STEP PTRACE_SINGLESTEP
#endif

#if !defined(PT_GETREGS) && defined(PTRACE_GETREGS)
#  define PT_GETREGS PTRACE_GETREGS
#endif

#if !defined(PT_SETREGS) && defined(PTRACE_SETREGS)
#  define PT_SETREGS PTRACE_SETREGS
#endif

#if !defined(PT_GETFPREGS) && defined(PTRACE_GETFPREGS)
#  define PT_GETFPREGS PTRACE_GETFPREGS
#endif

#if !defined(PT_SETFPREGS) && defined(PTRACE_SETFPREGS)
#  define PT_SETFPREGS PTRACE_SETFPREGS
#endif

#if !defined(PT_ATTACH) && defined(PTRACE_ATTACH)
#  define PT_ATTACH PTRACE_ATTACH
#endif

#if !defined(PT_DETACH) && defined(PTRACE_DETACH)
#  define PT_DETACH PTRACE_DETACH
#endif

#if !defined(PT_SYSCALL) && defined(PTRACE_SYSCALL)
#  define PT_SYSCALL PTRACE_SYSCALL
#endif

/*
 * Prototypes
 */

struct debugWorkspace;

int x86initRegistersDebug(struct debugWorkspace *ws);
unsigned long x86getCurrentInstruction(struct debugWorkspace *ws, int *err);
int x86setCurrentInstruction(struct debugWorkspace *ws, unsigned long address);
int x86getRegistersDebug(struct debugWorkspace *ws);
int x86readFPUDebug(struct debugWorkspace *ws, struct x86fpuInfo *fpuState);
int x86writeRegisterDebug(struct debugWorkspace *ws, struct x86RegInfo *rptr,
                          struct x86RegValue *regVal);

#endif /* INCLUDED_linux_x86_h */
