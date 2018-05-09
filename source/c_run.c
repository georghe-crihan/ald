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
 * $Id: c_run.c,v 1.1.1.1 2004/04/26 00:40:51 pa33 Exp $
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
 * libString includes
 */
#include "Strn.h"

/*
c_run()
  Run debugged process - start it from the beginning if it
is in the middle

Return: 0 upon failure
        1 upon success
*/

int
c_run(struct aldWorkspace *ws, int ac, char **av)

{
  int data,
      ret,
      restart;
  char *path;

  restart = 0;

  path = getPathDebug(ws->debugWorkspace_p);

  if (!path && awIsAttached(ws))
  {
    Print(ws,
          P_ERROR,
          "error: No path given for attached process (see help attach)");
    return (0);
  }

  if (isRunningDebug(ws->debugWorkspace_p))
  {
    if (BoolPrompt("Restart program from beginning? (y/n) "))
    {
      /*
       * Kill the old process
       */
      endDebug(ws->debugWorkspace_p);

      restart = 1;
    }
    else
      return (1); /* don't restart */
  }

  if (ac > 1)
  {
    char str[MAXLINE];
    char *tmp;
    int len,
        ii;

    /*
     * Runtime arguments supplied
     */

    len = sizeof(str);
    *str = '\0';
    tmp = str;

    for (ii = 1; ii < ac; ++ii)
    {
      tmp += Snprintf(tmp, len, "%s ", av[ii]);
      len = sizeof(str) - (int) (tmp - str);
    }

    if (*str)
      setArgsDebug(ws->debugWorkspace_p, str);
  } /* if (ac > 1) */

  /*
   * path may be NULL if we attached to the process
   */
  if (path)
  {
    char *args;

    args = getArgsDebug(ws->debugWorkspace_p);

    Print(ws,
          P_COMMAND,
          "%s program: %s %s",
          restart ? "Restarting" : "Starting",
          path,
          args ? args : "");
  }

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
} /* c_run() */
