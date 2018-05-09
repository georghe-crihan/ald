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
 * $Id: c_disable.c,v 1.1.1.1 2004/04/26 00:40:41 pa33 Exp $
 */

#include <stdlib.h>

#include "main.h"
#include "msg.h"
#include "print.h"

/*
 * libDebug includes
 */
#include "break.h"

/*
 * libString includes
 */
#include "Strn.h"

/*
c_disable()
  Disable a breakpoint

Return: 0 upon failure
        1 upon success
*/

int
c_disable(struct aldWorkspace *ws, int ac, char **av)

{
  unsigned long num;
  char *endptr;
  struct Breakpoint *ptr;

  if (ac < 2)
  {
    Print(ws, P_COMMAND, "Syntax: disable <number | all>");
    return (0);
  }

  if (!Strcasecmp(av[1], "all"))
    num = 0;
  else
  {
    num = strtoul(av[1], &endptr, 0);
    if ((endptr == av[1]) || (*endptr != '\0'))
    {
      Print(ws, P_ERROR, MSG_INVADDR, av[1]);
      return (0);
    }
  }

  if (num)
  {
    ptr = findBreakpointByNumber(ws->debugWorkspace_p, (unsigned int) num);
    if (!ptr)
      Print(ws, P_ERROR, "No such breakpoint number: %ld", num);
    else
      deactivateBreakpoint(ws->debugWorkspace_p, ptr);
  }
  else
    deactivateBreakpoint(ws->debugWorkspace_p, 0);

  return (1);
} /* c_disable() */
