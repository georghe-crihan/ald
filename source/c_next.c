/*
 * Assembly Language Debugger
 *
 * Copyright (C) 2000 Patrick Alken
 * This program comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: c_next.c,v 1.2 2004/10/10 03:07:56 pa33 Exp $
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "alddefs.h"
#include "disassemble.h"
#include "display.h"
#include "load.h"
#include "main.h"
#include "misc.h"
#include "msg.h"
#include "print.h"
#include "registers.h"
#include "set.h"
#include "signals.h"
#include "terminal.h"
#include "traceresult.h"

#include "libDebug.h"

/*
 * libString includes
 */
#include "alloc.h"

/*
c_next()
  Step through program, stepping over subroutines

Return: 0 upon failure
        1 upon success
*/

int
c_next(struct aldWorkspace *ws, int ac, char **av)

{
  int data, /* data returned from single step procedure */
      num,  /* number of instructions to step */
      ret;
  char *endptr;

  if (ac > 1)
  {
    num = strtol(av[1], &endptr, 0);
    if ((endptr == av[1]) || (*endptr != '\0'))
    {
      Print(ws, P_ERROR, MSG_INVNUM, av[1]);
      return (0);
    }
  }
  else
    num = 1;

  /*
   * Restore the child's terminal state
   */
  restoreTerminal(&(ws->terminalWorkspace_p->ChildAttributes));
  
  ret = stepOverDebug(ws->debugWorkspace_p, num, &data);

  /*
   * Save the child's terminal state and restore the original
   * terminal settings in case the child messed with them.
   */
  saveTerminal(&(ws->terminalWorkspace_p->ChildAttributes));
  restoreTerminal(&(ws->terminalWorkspace_p->ParentAttributes));

  if (analyzeTraceResult(ws, ret, data) == 0)
    return (0);

#if 0
  displayRegisters(ws, NOREG, 1, ws->stepDisplayFlags);

  DisplayNextInstruction(ws);
#endif

  doStepDisplay(ws);

  return (1);
} /* c_next() */
