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
 * $Id: c_break.c,v 1.1.1.1 2004/04/26 00:40:51 pa33 Exp $
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

#include "libOFF.h"

/*
c_break()
  Set a breakpoint at given address

Return: 0 upon failure
        1 upon success
*/

int
c_break(struct aldWorkspace *ws, int ac, char **av)

{
  unsigned long address;
  int num;
  char *endptr;
  struct offSymbolInfo symInfo;

  if (ac < 2)
  {
    Print(ws, P_COMMAND, "Syntax: break <address | symbol>");
    return (0);
  }

  address = strtoul(av[1], &endptr, 0);
  if ((endptr == av[1]) || (*endptr != '\0'))
  {
    int err;

    /*
     * They gave an invalid number, but it may be the name
     * of a debugging symbol
     */
    err = 0;
    if (!findSymbolOFF(ws->offWorkspace_p, av[1], 0, &symInfo))
    {
      Print(ws, P_ERROR, MSG_INVSYM, av[1]);
      return (0);
    }

    address = symInfo.address;
  }

  num = newBreakpoint(ws->debugWorkspace_p, address, 0);

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
    Print(ws, P_COMMAND, "Breakpoint %u set for 0x%08lX",
      num,
      address);
  }

  return (1);
} /* c_break() */
