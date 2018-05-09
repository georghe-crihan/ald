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
 * $Id: c_ignore.c,v 1.1.1.1 2004/04/26 00:40:46 pa33 Exp $
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
c_ignore()
  Set the ignore count for a breakpoint

Return: 0 upon failure
        1 upon success
*/

int
c_ignore(struct aldWorkspace *ws, int ac, char **av)

{
  unsigned long num;
  long count;
  char *endptr;
  struct Breakpoint *ptr;

  if (ac < 3)
  {
    Print(ws, P_COMMAND, "Syntax: ignore <number> <count>");
    return (0);
  }

  num = strtoul(av[1], &endptr, 0);
  if ((endptr == av[1]) || (*endptr != '\0'))
  {
    Print(ws, P_ERROR, MSG_INVNUM, av[1]);
    return (0);
  }

  ptr = findBreakpointByNumber(ws->debugWorkspace_p, (unsigned int) num);
  if (!ptr)
  {
    Print(ws, P_ERROR, "No such breakpoint number: %ld", num);
    return (0);
  }

  count = strtol(av[2], &endptr, 0);
  if ((endptr == av[2]) || (*endptr != '\0'))
  {
    Print(ws, P_ERROR, MSG_INVNUM, av[2]);
    return (0);
  }

  setIgnoreCount(ptr, count);

  return (1);
} /* c_ignore() */
