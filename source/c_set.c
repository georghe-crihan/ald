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
 * $Id: c_set.c,v 1.1.1.1 2004/04/26 00:40:49 pa33 Exp $
 */

#include "alddefs.h"
#include "command.h"
#include "main.h"
#include "print.h"
#include "set.h"

/*
c_set()
  Configure various settings

Return: 0 upon failure
        1 upon success
*/

int
c_set(struct aldWorkspace *ws, int ac, char **av)

{
  struct Command *cptr;
  unsigned int flags;
  int ret;
  char errbuf[MAXLINE];

  if (ac < 2)
  {
    DisplaySettings(ws);
    return (0);
  }

  flags = 0;
  cptr = FindSetCommand(av[1], &flags);

  if (!cptr)
  {
    /*
     * They gave us an invalid setting
     */
    Print(ws,
          P_COMMAND,
          "%s command: set %s",
          (flags & C_AMBIGUOUS) ? "Ambiguous" : "Unknown",
          av[1]);
    return (0);
  }

  /*
   * Call cptr->func to execute command
   */
  ret = (*cptr->funcptr)(ws, ac, av, 0, errbuf);

  switch (ret)
  {
    /* general error */
    case 0:
    {
      Print(ws,
            P_COMMAND,
            "%s",
            errbuf);

      return (0);

      break;
    }

    /* syntax error */
    case 1:
    {
      Print(ws,
            P_COMMAND,
            "Syntax: %s",
            errbuf);

      return (0);

      break;
    }

    /* success */
    default:
    {
      break;
    }
  }

  return (1);
} /* c_set() */
