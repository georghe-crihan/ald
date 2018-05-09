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
 * $Id: break.h,v 1.1.1.1 2004/04/26 00:41:11 pa33 Exp $
 */

#ifndef INCLUDED_libDebug_break_h
#define INCLUDED_libDebug_break_h

struct Breakpoint
{
  struct Breakpoint *next, *prev;

  unsigned int number;   /* breakpoint number */
  unsigned long address; /* instruction address */
  unsigned int flags;    /* BK_xxx bitmasks */

  /*
   * This is the instruction we overwrite with our break point
   * instruction
   */
  int svdinsn;

  /*
   * Number of times we should ignore the breakpoint when we
   * hit it. When this number reaches 0, the breakpoint is no
   * longer ignored.
   */
  int ignorecnt;

  int hitcnt;            /* number of times we hit this breakpoint */
};

#define BK_ENABLED      (1 << 0) /* breakpoint is activated */
#define BK_TEMPORARY    (1 << 1) /* temporary breakpoint */
#define BK_STEPOVER     (1 << 2) /* stepping over subroutine */
#define BK_NOTSAVED     (1 << 3) /* we have not stored instruction in svdinsn yet */

/*
 * Prototypes
 */

struct debugWorkspace;

void deleteBreakpoint(struct debugWorkspace *ws, struct Breakpoint *ptr);
void clearBreakpoints(struct debugWorkspace *ws);
void clearTemporaryBreakpoints(struct debugWorkspace *ws);
int newBreakpoint(struct debugWorkspace *ws, unsigned long address, unsigned int flags);
int setAndSaveBreakpoint(struct debugWorkspace *ws, unsigned long address,
                         unsigned int flags);
int enableBreakpoints(struct debugWorkspace *ws);
int disableBreakpoints(struct debugWorkspace *ws);
struct Breakpoint *findBreakpoint(struct debugWorkspace *ws, unsigned long address);
struct Breakpoint *findBreakpointByNumber(struct debugWorkspace *ws, unsigned int number);
int checkBreakpoint(struct debugWorkspace *ws, struct Breakpoint *bptr);
void deactivateBreakpoint(struct debugWorkspace *ws,struct Breakpoint *ptr);
void activateBreakpoint(struct debugWorkspace *ws, struct Breakpoint *ptr);
void setIgnoreCount(struct Breakpoint *ptr, long count);

#endif /* INCLUDED_libDebug_break_h */
