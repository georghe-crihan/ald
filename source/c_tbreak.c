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
 * $Id: c_tbreak.c,v 1.1.1.1 2004/04/26 00:40:45 pa33 Exp $
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "main.h"
#include "msg.h"
#include "print.h"

/*
 * libDebug includes
 */
#include "break.h"

/*
c_tbreak()
  Set a temporary breakpoint at given address

Return: 0 upon failure
        1 upon success
*/

int
c_tbreak(struct aldWorkspace *ws, int ac, char **av)

{
  unsigned long address;
  int num;
  char *endptr;

  if (ac < 2)
  {
    Print(ws, P_COMMAND, "Syntax: tbreak <address>");
    return (0);
  }

  address = strtoul(av[1], &endptr, 0);
  if ((endptr == av[1]) || (*endptr != '\0'))
  {
    Print(ws, P_ERROR, MSG_INVADDR, av[1]);
    return (0);
  }

  num = newBreakpoint(ws->debugWorkspace_p, address, BK_TEMPORARY);

  if (num == (-1))
  {
    /*
     * Most likely a ptrace error
     */
    Print(ws, P_COMMAND, "Error occurred while setting breakpoint: %s",
      strerror(errno));
  }
  else
  {
    Print(ws, P_COMMAND, "Breakpoint %u set for 0x%08lX (temporary)",
      num,
      address);
  }

  return (1);
} /* c_tbreak() */
