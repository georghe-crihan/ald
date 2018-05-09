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
 * $Id: c_attach.c,v 1.1.1.1 2004/04/26 00:40:49 pa33 Exp $
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "disassemble.h"
#include "main.h"
#include "msg.h"
#include "print.h"
#include "registers.h"
#include "set.h"

/*
c_attach()
  Attach debugger to a currently running process

Format for this command:
  attach <pid>

Return: 0 upon failure
        1 upon success
*/

int
c_attach(struct aldWorkspace *ws, int ac, char **av)

{
  int pid;
  char *endptr;

  if (ac < 2)
  {
    Print(ws, P_COMMAND, "Syntax: attach <pid>");
    return (0);
  }

  pid = (int) strtol(av[1], &endptr, 0);
  if ((endptr == av[1]) || (*endptr != '\0'))
  {
    Print(ws, P_COMMAND, "Invalid pid: %s", av[1]);
    return (0);
  }

  if (!attachDebug(ws->debugWorkspace_p, pid))
  {
    Print(ws,
          P_ERROR,
          MSG_PTERR,
          strerror(errno));
    return (0);
  }

  Print(ws,
        P_COMMAND,
        "Attached to process id %d",
        pid);

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

  awSetAttached(ws);

  return (1);
} /* c_attach() */
