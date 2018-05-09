/*
 * Assembly Language Debugger
 *
 * Copyright (C) 2004 Patrick Alken
 * This program comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: display.c,v 1.3 2004/10/10 05:29:50 pa33 Exp $
 *
 * This module contains the code which displays relevant information
 * on registers, memory, the next disassembled instruction, etc after
 * each single step or when the program halts execution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "disassemble.h"
#include "display.h"
#include "main.h"
#include "list.h"
#include "msg.h"
#include "registers.h"

/*
addStepDisplay()
  Add a new range of memory to be displayed after each single
step.

Inputs: ws        - main workspace
        startaddr - starting address
        numbytes  - number of bytes
        elsize    - size of each element
        output    - output type (hex, octal, etc)

Return: 1 if successful
        0 if not
*/

int
addStepDisplay(struct aldWorkspace *ws, unsigned long startaddr,
               long numbytes, long elsize, unsigned char output)

{
  struct stepDisplay *ptr;

  ptr = (struct stepDisplay *) malloc(sizeof(struct stepDisplay));
  if (!ptr)
  {
    fprintf(stderr, "addStepDisplay: malloc failed: %s\n",
            strerror(errno));
    return (0);
  }

  memset(ptr, 0, sizeof(struct stepDisplay));

  ptr->startaddr = startaddr;
  ptr->numbytes = numbytes;
  ptr->elsize = elsize;
  ptr->output = output;
  ptr->number = ++(ws->stepDisplayNum);

  /*
   * Insert into linked list of things to display after
   * single steps
   */
  if (insertList(&(ws->stepDisplayList), (void *) ptr))
    return (1);
  else
    return (0);
} /* addStepDisplay() */

/*
doStepDisplay()
  Called after each single step or when the program stops execution
in order to display relevant registers, memory, next disassembled
instruction, etc.

Inputs: ws - main workspace

Return: none
*/

void
doStepDisplay(struct aldWorkspace *ws)

{
  struct stepDisplay *sptr;
  struct genericList *ptr;
  unsigned char *membuf;
  long ndumped;

  /*
   * Display register list
   */
  displayRegisters(ws, NOREG, 1, ws->stepDisplayFlags);

  /*
   * Display memory locations
   */
  ptr = ws->stepDisplayList;
  while (ptr)
  {
    sptr = (struct stepDisplay *) ptr->ptr;

    membuf = 0;
    ndumped = dumpMemoryDebug(ws->debugWorkspace_p,
                              &membuf,
                              sptr->startaddr,
                              sptr->numbytes);

    if (ndumped > 0)
    {
      OutputMemory(ws,
                   membuf,
                   sptr->startaddr,
                   ndumped,
                   sptr->elsize,
                   sptr->output);
      free(membuf);
    }

    if (ndumped < sptr->numbytes)
    {
      Print(ws,
            P_ERROR,
            MSG_NOACCESS,
            sptr->startaddr + ndumped,
            strerror(errno));
    }

    ptr = ptr->next;
  } /* while (ptr) */

  DisplayNextInstruction(ws);
} /* doStepDisplay() */

struct genericList *
findStepDisplayByNumber(struct aldWorkspace *ws, unsigned int num)

{
  struct genericList *node;

  node = ws->stepDisplayList;
  while (node)
  {
    if (((struct stepDisplay *)(node->ptr))->number == num)
      return (node);

    node = node->next;
  }

  return (0);
} /* findStepDisplayByNumber() */
