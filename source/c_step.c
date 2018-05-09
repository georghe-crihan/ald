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
 * $Id: c_step.c,v 1.1.1.1 2004/04/26 00:40:45 pa33 Exp $
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "alddefs.h"
#include "disassemble.h"
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
c_step()
  Step through program, stepping into subroutines

Return: 0 upon failure
        1 upon success
*/

int
c_step(struct aldWorkspace *ws, int ac, char **av)

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

  ret = stepIntoDebug(ws->debugWorkspace_p, num, &data);

  /*
   * Save the child's terminal state and restore the original
   * terminal settings in case the child messed with them.
   */
  saveTerminal(&(ws->terminalWorkspace_p->ChildAttributes));
  restoreTerminal(&(ws->terminalWorkspace_p->ParentAttributes));

  if (analyzeTraceResult(ws, ret, data) == 0)
    return (0);

  if (IsSetStepDisplayRegs(ws))
  {
    /*
     * Update and display new register values
     */
    displayRegisters(ws, NOREG, 1, DB_REGFL_DISPLAY_GENERAL);
  }

  if (IsSetStepDisplayFpRegs(ws))
    displayRegisters(ws, NOREG, 1, DB_REGFL_DISPLAY_FPREGS);

  if (IsSetStepDisplayMmxRegs(ws))
    displayRegisters(ws, NOREG, 1, DB_REGFL_DISPLAY_MMXREGS);

  /*
   * Disassemble and output the next instruction
   */
  DisplayNextInstruction(ws);

  return (1);
} /* c_step() */
