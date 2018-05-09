/*
 * Assembly Language Debugger
 *
 * Copyright (C) 2004 Patrick Alken
 * This program comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: c_undisplay.c,v 1.1 2004/10/10 05:29:50 pa33 Exp $
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "alddefs.h"
#include "defs.h"
#include "display.h"
#include "list.h"
#include "main.h"
#include "msg.h"
#include "print.h"

#include "libDebug.h"

/*
 * libString includes
 */
#include "Strn.h"

/*
c_undisplay()
  Remove a single step display entry

Format for this command:
undisplay <number | all>

where <number> can be obtained from "ldisplay"

Return: 0 upon failure
        1 upon success
*/

int
c_undisplay(struct aldWorkspace *ws, int ac, char **av)

{
  unsigned long num;
  struct genericList *node;
  char *endptr;

  if (ac < 2)
  {
    Print(ws, P_COMMAND, "Syntax: undisplay <number | all>");
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
    node = findStepDisplayByNumber(ws, num);
    if (!node)
      Print(ws, P_ERROR, "No such display number: %lu", num);
    else
    {
      free(node->ptr);
      deleteList(&(ws->stepDisplayList), node);
    }
  }
  else
    freeList(&(ws->stepDisplayList));

  return (1);
} /* c_undisplay() */
