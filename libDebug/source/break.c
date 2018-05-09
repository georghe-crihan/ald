/*
 * libDebug
 *
 * Copyright (C) 2000 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: break.c,v 1.1.1.1 2004/04/26 00:41:11 pa33 Exp $
 */

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "break.h"
#include "libDebug.h"

static struct Breakpoint *createBreakpoint(struct debugWorkspace *ws);
static void unlinkBreakpoint(struct Breakpoint *ptr,
                             struct Breakpoint **list);
static int setBreakpoint(struct debugWorkspace *ws,
                         unsigned long address,
                         unsigned int flags);

/*
createBreakpoint()
  Create a Breakpoint structure
*/

static struct Breakpoint *
createBreakpoint(struct debugWorkspace *ws)

{
  struct Breakpoint *ptr;

  ptr = (struct Breakpoint *) malloc(sizeof(struct Breakpoint));
  memset(ptr, '\0', sizeof(struct Breakpoint));

  ptr->prev = 0;
  ptr->next = ws->breakpoints;
  if (ptr->next)
    ptr->next->prev = ptr;

  ws->breakpoints = ptr;

  return (ptr);
} /* createBreakpoint() */

/*
deleteBreakpoint()
  Remove breakpoint from list and free it
*/

void
deleteBreakpoint(struct debugWorkspace *ws, struct Breakpoint *ptr)

{
  unlinkBreakpoint(ptr, &(ws->breakpoints));
  free(ptr);
} /* deleteBreakpoint() */

/*
unlinkBreakpoint()
  Unlink breakpoint from linked list

Inputs: ptr  - structure to unlink
        list - list to unlink from
*/

static void
unlinkBreakpoint(struct Breakpoint *ptr, struct Breakpoint **list)

{
  assert(ptr != 0);

  if (ptr->next)
    ptr->next->prev = ptr->prev;

  if (ptr->prev)
    ptr->prev->next = ptr->next;
  else
    *list = ptr->next;
} /* unlinkBreakpoint() */

/*
clearBreakpoints()
  Delete all breakpoints
*/

void
clearBreakpoints(struct debugWorkspace *ws)

{
  struct Breakpoint *ptr,
                    *next;

  ptr = ws->breakpoints;
  while (ptr)
  {
    next = ptr->next;
    deleteBreakpoint(ws, ptr);
    ptr = next;
  }
} /* clearBreakpoints() */

/*
clearTemporaryBreakpoints()
  Delete all temporary breakpoints
*/

void
clearTemporaryBreakpoints(struct debugWorkspace *ws)

{
  struct Breakpoint *ptr,
                    *next;

  ptr = ws->breakpoints;
  while (ptr)
  {
    next = ptr->next;

    if (ptr->flags & BK_TEMPORARY)
      deleteBreakpoint(ws, ptr);

    ptr = next;
  }
} /* clearTemporaryBreakpoints() */

/*
newBreakpoint()
*/

int
newBreakpoint(struct debugWorkspace *ws, unsigned long address, unsigned int flags)

{
  if (dbIsRunning(ws))
    return (setAndSaveBreakpoint(ws, address, flags));
  else
    return (setBreakpoint(ws, address, flags));
} /* newBreakpoint() */

/*
setBreakpoint()
  This routine is called when the external user wants to set a breakpoint, but has
not yet begun running the process. In this case we create the necessary breakpoint
structures, but we do *not* save the instruction at the location where the breakpoint
is to be placed. The reason for this is in order to save that instruction we would
need to execv() the process, but since the external user has not yet begun running
the process, they may want to specify arguments at a later time. If we execv() now,
we will miss those possible runtime arguments.

Inputs: ws      - debug workspace
        address - instruction address for breakpoint
        flags   - various flags for the breakpoint

Return: breakpoint number, or -1 if error occurs
*/

static int
setBreakpoint(struct debugWorkspace *ws, unsigned long address, unsigned int flags)

{
  struct Breakpoint *bptr;

  bptr = createBreakpoint(ws);

  bptr->number = ws->breakNumber;
  bptr->address = address;
  bptr->flags = flags | BK_ENABLED | BK_NOTSAVED;

  ++(ws->breakNumber);

  /*
   * Set a flag indicating there is at least one breakpoint to be saved
   */
  dbSetPendingBreakSaves(ws);

  return ((int) bptr->number);
} /* setBreakpoint() */

/*
setAndSaveBreakpoint()
  This routine is called when we want to set a breakpoint and the debugged process
is already running. In this case it is ok to save the contents of the location where
the breakpoint is to be placed.

Inputs: ws      - debug workspace
        address - instruction address for breakpoint
        flags   - various flags for the breakpoint

Return: breakpoint number, or -1 if error occurs
*/

int
setAndSaveBreakpoint(struct debugWorkspace *ws, unsigned long address,
                     unsigned int flags)

{
  struct Breakpoint *bptr;
  int ret;

  bptr = createBreakpoint(ws);

  bptr->number = ws->breakNumber;
  bptr->address = address;
  bptr->flags = flags | BK_ENABLED;

  /*
   * Save the contents of the memory address into bptr->svdinsn
   */
  ret = x86saveBreakpoint(ws, bptr);

  if (!ret)
  {
    deleteBreakpoint(ws, bptr);
    return (-1);
  }
  else
  {
    /*
     * Do not increment ws->breakNumber if this breakpoint is
     * only being used to step over a subroutine.
     */
    if (!(flags & BK_STEPOVER))
      ++(ws->breakNumber);

    return ((int) bptr->number);
  }
} /* setAndEnableBreakpoint() */

/*
enableBreakpoints()
  Enable all breakpoints by setting the first byte of their
memory addresses to the breakpoint instruction

Return: 1 if successful
        0 if not
*/

int
enableBreakpoints(struct debugWorkspace *ws)

{
  struct Breakpoint *bptr;
  int ret = 1;

  assert(ws->pid != NOPID);

  if (dbIsPendingBreakSaves(ws))
  {
    /*
     * There are breakpoints in ws->breakpoints whose corresponding
     * memory locations have not yet been saved, so go through and
     * save them now. This cannot be done in the main loop below
     * because if two breakpoints are close together, the first will
     * be saved and then enabled, and so when the second is saved one
     * of it's bytes will be the breakpoint instruction.
     */
    for (bptr = ws->breakpoints; bptr; bptr = bptr->next)
    {
      if (bptr->flags & BK_NOTSAVED)
      {
        if (!x86saveBreakpoint(ws, bptr))
        {
          ret = 0;
          continue;
        }
        else
          bptr->flags &= ~BK_NOTSAVED;
      }
    }

    dbClearPendingBreakSaves(ws);
  } /* if (dbIsPendingBreakSaves(ws)) */

  for (bptr = ws->breakpoints; bptr; bptr = bptr->next)
  {
    if (bptr->flags & BK_ENABLED)
    {
      if (!x86enableBreakpoint(ws, bptr))
        ret = 0;
    }
  }

  return (ret);
} /* enableBreakpoints() */

/*
disableBreakpoints()
  Restore breakpoint addresses with their original instructions

Return: 1 if successful
        0 if not
*/

int
disableBreakpoints(struct debugWorkspace *ws)

{
  struct Breakpoint *bptr;
  int ret = 1;

  assert(ws->pid != NOPID);

  for (bptr = ws->breakpoints; bptr; bptr = bptr->next)
  {
    if (bptr->flags & BK_ENABLED)
    {
      if (!x86disableBreakpoint(ws, bptr))
        ret = 0;
    }
  }

  return (ret);
} /* disableBreakpoints() */

/*
findBreakpoint()
  Find a certain breakpoint structure

Inputs: ws      - debug workspace
        address - address of breakpoint

Return: pointer to Breakpoint structure
*/

struct Breakpoint *
findBreakpoint(struct debugWorkspace *ws, unsigned long address)

{
  struct Breakpoint *ptr;

  for (ptr = ws->breakpoints; ptr; ptr = ptr->next)
  {
    if (ptr->address == address)
      return (ptr);
  }

  return (0);
} /* findBreakpoint() */

/*
findBreakpointByNumber()
  Find a certain breakpoint structure

Inputs: ws     - debug workspace
        number - breakpoint number

Return: pointer to Breakpoint structure
*/

struct Breakpoint *
findBreakpointByNumber(struct debugWorkspace *ws, unsigned int number)

{
  struct Breakpoint *ptr;

  for (ptr = ws->breakpoints; ptr; ptr = ptr->next)
  {
    if (ptr->number == number)
      return (ptr);
  }

  return (0);
} /* findBreakpointByNumber() */

/*
checkBreakpoint()
  Called when a breakpoint is encountered - check to see if it
is time to delete it and if not, update it's hit count

Inputs: ws   - debug workspace
        bptr - breakpoint which was encountered

Return: 1 if breakpoint is deleted from list
        0 if not
*/

int
checkBreakpoint(struct debugWorkspace *ws, struct Breakpoint *bptr)

{
  if (bptr->flags & BK_TEMPORARY)
  {
    /*
     * A breakpoint has the temporary flag set if it is only
     * to be used once. Since this breakpoint was just hit,
     * remove it from our list.
     */
    deleteBreakpoint(ws, bptr);
    return (1);
  }

  /*
   * No need to delete this breakpoint - update it's hit count
   */
  ++(bptr->hitcnt);

  return (0);
} /* checkBreakpoint() */

/*
deactivateBreakpoint()
  Mark a breakpoint as inactive

Inputs: ws  - debug workspace
        ptr - breakpoint pointer

Return: none
*/

void
deactivateBreakpoint(struct debugWorkspace *ws, struct Breakpoint *ptr)

{
  struct Breakpoint *bptr;

  if (!ptr)
  {
    /*
     * A null pointer means disable all breakpoints
     */
    for (bptr = ws->breakpoints; bptr; bptr = bptr->next)
      bptr->flags &= ~BK_ENABLED;
  }
  else
    ptr->flags &= ~BK_ENABLED;
} /* deactivateBreakpoint() */

/*
activateBreakpoint()
  Mark a breakpoint as active

Inputs: ws  - debug workspace
        ptr - breakpoint pointer

Return: none
*/

void
activateBreakpoint(struct debugWorkspace *ws,struct Breakpoint *ptr)

{
  struct Breakpoint *bptr;

  if (!ptr)
  {
    /*
     * A null pointer means enable all breakpoints
     */
    for (bptr = ws->breakpoints; bptr; bptr = bptr->next)
      bptr->flags |= BK_ENABLED;
  }
  else
    ptr->flags |= BK_ENABLED;
} /* activateBreakpoint() */

/*
setIgnoreCount()
  Set the ignore count for a breakpoint

Inputs: ptr   - breakpoint
        count - new ignore count
*/

void
setIgnoreCount(struct Breakpoint *ptr, long count)

{
  assert(ptr != 0);

  ptr->ignorecnt = count;
} /* setIgnoreCount() */
