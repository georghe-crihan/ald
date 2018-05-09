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
 * $Id: libDebug.h,v 1.4 2004/10/09 17:34:15 pa33 Exp $
 */

#ifndef INCLUDED_libDebug_libDebug_h
#define INCLUDED_libDebug_libDebug_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>          /* pid_t */
#define INCLUDED_sys_types_h
#endif

#ifndef INCLUDED_api_cfgDebug_h
#include "api_cfgDebug.h"
#define INCLUDED_api_cfgDebug_h
#endif

#ifndef INCLUDED_libDebug_args_h
#include "args.h"
#define INCLUDED_libDebug_args_h
#endif

#ifndef INCLUDED_libDebug_break_h
#include "break.h"
#define INCLUDED_libDebug_break_h
#endif

#ifndef INCLUDED_libDebug_version_h
#include "version.h"
#define INCLUDED_libDebug_version_h
#endif

/*
 * regs-x86.h must be included before linux-x86.h and bsd-x86.h
 */

#ifndef INCLUDED_regs_x86_h
#include "../arch/ix86/include/regs-x86.h"
#define INCLUDED_regs_x86_h
#endif

#ifdef OS_LINUX

#ifndef INCLUDED_linux_x86_h
#include "../arch/ix86/include/linux-x86.h"
#define INCLUDED_linux_x86_h
#endif

#endif /* OS_LINUX */

#ifdef OS_BSD

#ifndef INCLUDED_bsd_x86_h
#include "../arch/ix86/include/bsd-x86.h"
#define INCLUDED_bsd_x86_h
#endif

#endif /* OS_BSD */

#ifndef INCLUDED_sub_x86_h
#include "../arch/ix86/include/sub-x86.h"
#define INCLUDED_sub_x86_h
#endif

#ifndef INCLUDED_trace_x86_h
#include "../arch/ix86/include/trace-x86.h"
#define INCLUDED_trace_x86_h
#endif

typedef struct x86RegisterContents debugRegisterContents;

/*
 * Indicates there is no process currently being traced
 */
#define NOPID     (-1)

#ifndef MAXLINE
#define MAXLINE   1024
#endif

struct debugRegisterInfo
{
  char name[MAXLINE];               /* register name */
  size_t size;                      /* register size in bytes times 2 */

  unsigned long value;              /* register value */

  unsigned char *rawbuf;            /* pointer to raw register contents */
  char hexvalue[MAXLINE];           /* register hexadecimal value in ascii format */

  unsigned short seg;               /* possible segment selector */
  unsigned long off;                /* possible offset */

  unsigned int flags;               /* DB_RI_xxx */
};

/*
 * Bitmask flags for debugRegisterInfo structure
 */
#define DB_RI_GENERAL                (1 << 0) /* general register */
#define DB_RI_FPU_DATA               (1 << 1) /* floating point unit data register */
#define DB_RI_FPU_SEGOFF             (1 << 2) /* fpu register with segment/offset */
#define DB_RI_MMX                    (1 << 3) /* mmx register */
#define DB_RI_BREAK                  (1 << 4) /* indicates a new batch of registers */

struct debugWorkspace
{
  pid_t pid;                        /* process id of debugged program */
  char *path;                       /* path to debugged program */
  char output[MAXLINE];             /* buffer for debug output */

  char *argsLinear;                 /* debug arguments */
  char **args;
  char argbuf[MAXLINE];             /* temporary buffer for argument parsing */

  unsigned long instructionPointer; /* address of next instruction to be executed */

  int pipes[2];                     /* file descriptors for redirected io */

  struct Breakpoint *breakpoints;   /* list of breakpoints */
  unsigned int breakNumber;         /* used to assign breakpoint numbers */

  int lastSignal;                   /* last signal received */

  unsigned int flags;               /* bitmask (DB_xxx) */

  void *fpuState;                   /* fpu state */

  struct debugRegisterInfo regInfo; /* info for a register */

  debugRegisterContents regContents; /* contents of all registers */

  char scratch1[MAXLINE];           /* scratch buffers */
  char scratch2[MAXLINE];
};

/*
 * Bitmask flags
 */
#define DB_REDIRECTIO                (1 << 0)  /* redirect io */
#define DB_RUNNING                   (1 << 1)  /* process is running */
#define DB_HITBREAKPOINT             (1 << 2)  /* hit a breakpoint */
#define DB_ATTACHED                  (1 << 3)  /* attached to a process via PT_ATTACH */
#define DB_PENDING_BREAK_SAVES       (1 << 4)  /* there are unsaved breakpoints */

#define dbSetRedirect(x)             ((x)->flags |= DB_REDIRECTIO)
#define dbSetRunning(x)              ((x)->flags |= DB_RUNNING)
#define dbSetHitBreakpoint(x)        ((x)->flags |= DB_HITBREAKPOINT)
#define dbSetAttached(x)             ((x)->flags |= DB_ATTACHED)
#define dbSetPendingBreakSaves(x)    ((x)->flags |= DB_PENDING_BREAK_SAVES)

#define dbIsRedirect(x)              ((x)->flags & DB_REDIRECTIO)
#define dbIsRunning(x)               ((x)->flags & DB_RUNNING)
#define dbHitBreakpoint(x)           ((x)->flags & DB_HITBREAKPOINT)
#define dbIsAttached(x)              ((x)->flags & DB_ATTACHED)
#define dbIsPendingBreakSaves(x)     ((x)->flags & DB_PENDING_BREAK_SAVES)

#define dbClearRedirect(x)           ((x)->flags &= ~DB_REDIRECTIO)
#define dbClearRunning(x)            ((x)->flags &= ~DB_RUNNING)
#define dbClearHitBreakpoint(x)      ((x)->flags &= ~DB_HITBREAKPOINT)
#define dbClearAttached(x)           ((x)->flags &= ~DB_ATTACHED)
#define dbClearPendingBreakSaves(x)  ((x)->flags &= ~DB_PENDING_BREAK_SAVES)

/*
 * Flags to be passed to printRegistersDebug()
 */
#define DB_REGFL_DISPLAY_GENERAL     (1 << 0) /* display general registers */
#define DB_REGFL_DISPLAY_FPREGS      (1 << 1) /* display floating point registers */
#define DB_REGFL_DISPLAY_MMXREGS     (1 << 2) /* display mmx registers */

#define DB_REGFL_DISPLAY_ALL         (DB_REGFL_DISPLAY_GENERAL | \
                                      DB_REGFL_DISPLAY_FPREGS | \
                                      DB_REGFL_DISPLAY_MMXREGS)

/*
 * Prototypes
 */

struct debugWorkspace *initDebug();
void termDebug(struct debugWorkspace *ws);
void startDebug(struct debugWorkspace *ws, char *path, int redirect);
void endDebug(struct debugWorkspace *ws);
unsigned long getAddressDebug(struct debugWorkspace *ws);
int isRunningDebug(struct debugWorkspace *ws);
char *getOutputDebug(struct debugWorkspace *ws);
char *getArgsDebug(struct debugWorkspace *ws);
void setArgsDebug(struct debugWorkspace *ws, char *args);
char *getPathDebug(struct debugWorkspace *ws);

int killDebug(struct debugWorkspace *ws);
int printRegistersDebug(struct debugWorkspace *ws, int regindex, unsigned int flags,
                        void (*callback)(), void *callbackArgs);
int stepIntoDebug(struct debugWorkspace *ws, int num, int *data);
int stepOverDebug(struct debugWorkspace *ws, int num, int *data);
int continueDebug(struct debugWorkspace *ws, int *data);
int findRegisterDebug(struct debugWorkspace *ws, char *name);
int setRegisterDebug(struct debugWorkspace *ws, int regindex, char *value);
long readRegisterDebug(struct debugWorkspace *ws, int regindex);
int getFlagsDebug(struct debugWorkspace *ws, char *flags);
long dumpMemoryDebug(struct debugWorkspace *ws, unsigned char **buf,
                     unsigned long start, unsigned long bytes);
int setMemoryDebug(struct debugWorkspace *ws, unsigned long address, unsigned long value);
int attachDebug(struct debugWorkspace *ws, int pid);
int detachDebug(struct debugWorkspace *ws);

#endif /* INCLUDED_libDebug_libDebug_h */
