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
 * $Id: c_dbreak.c,v 1.1 2004/10/10 03:07:56 pa33 Exp $
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
c_dbreak()
  Delete a breakpoint

Return: 0 upon failure
        1 upon success
*/

int
c_dbreak(struct aldWorkspace *ws, int ac, char **av)

{
  unsigned long num;
  char *endptr;
  struct Breakpoint *ptr;

  if (ac < 2)
  {
    Print(ws, P_COMMAND, "Syntax: dbreak <number | all>");
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
      deleteBreakpoint(ws->debugWorkspace_p, ptr);
  }
  else
    clearBreakpoints(ws->debugWorkspace_p);

  return (1);
} /* c_dbreak() */
