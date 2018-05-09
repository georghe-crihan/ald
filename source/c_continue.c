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
 * $Id: c_continue.c,v 1.1.1.1 2004/04/26 00:40:49 pa33 Exp $
 */

#include <errno.h>
#include <string.h>
#include <assert.h>

#include "disassemble.h"
#include "load.h"
#include "main.h"
#include "misc.h"
#include "msg.h"
#include "output.h"
#include "print.h"
#include "registers.h"
#include "set.h"
#include "signals.h"
#include "terminal.h"
#include "traceresult.h"

#include "libDebug.h"

/*
c_continue()
  Continue execution of debugged process from where it left off

Return: 0 upon failure
        1 upon success
*/

int
c_continue(struct aldWorkspace *ws, int ac, char **av)

{
  int data,
      ret;

  /*
   * Restore the child's terminal state
   */
  restoreTerminal(&(ws->terminalWorkspace_p->ChildAttributes));

  ret = continueDebug(ws->debugWorkspace_p, &data);

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

  DisplayNextInstruction(ws);

  return (1);
} /* c_continue() */
