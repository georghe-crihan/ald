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
 * $Id: c_enter.c,v 1.1.1.1 2004/04/26 00:40:45 pa33 Exp $
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "main.h"
#include "msg.h"
#include "output.h"
#include "print.h"

#include "libDebug.h"

/*
c_enter()
  Enter value(s) into memory

Format for this command:
  enter <address> [value]

Return: 0 upon failure
        1 upon success
*/

int
c_enter(struct aldWorkspace *ws, int ac, char **av)

{
  unsigned long address;
  unsigned long value;
  int gotvalue;
  char *endptr;

  if (ac < 2)
  {
    Print(ws, P_COMMAND, "Syntax: enter <address> [value]");
    return (0);
  }

  address = strtoul(av[1], &endptr, 0);
  if ((endptr == av[1]) || (*endptr != 0))
  {
    Print(ws, P_COMMAND, MSG_INVADDR, av[1]);
    return (0);
  }

  gotvalue = 0;
  value = 0;
  if (ac > 2)
  {
    value = strtoul(av[2], &endptr, 0);
    if ((endptr == av[2]) || (*endptr != '\0'))
    {
      Print(ws, P_COMMAND, MSG_INVADDR, av[2]);
      return (0);
    }
    gotvalue = 1;
  }

  if (gotvalue)
  {
    if (!setMemoryDebug(ws->debugWorkspace_p, address, value))
    {
      Print(ws, P_COMMAND, MSG_NOACCESS, address, strerror(errno));
      return (0);
    }
  }
  else
  {
    int done;
    int ret = 1;
    char str[MAXLINE];

    /*
     * No value given - prompt them to enter values
     */
    Print(ws,
          P_COMMAND,
          "Enter new memory contents starting at location 0x%08lX (leave blank to stop)",
          address);

    done = 0;
    while (!done)
    {
      sprintf(str, "0x%08lX: ", address);
      value = NumPrompt(str, &done);
      if (!done)
      {
        ret = setMemoryDebug(ws->debugWorkspace_p, address, value);
        if (ret == 0)
        {
          Print(ws, P_COMMAND, MSG_NOACCESS, address, strerror(errno));
          return (0);
        }
      }

      address += ret;
    } /* while (!done) */
  }

  return (1);
} /* c_enter() */
