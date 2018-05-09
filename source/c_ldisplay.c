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
 * $Id: c_ldisplay.c,v 1.1 2004/10/10 05:29:50 pa33 Exp $
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
c_ldisplay()
  Remove a single step display entry

Format for this command:
undisplay <number | all>

where <number> can be obtained from "ldisplay"

Return: 0 upon failure
        1 upon success
*/

int
c_ldisplay(struct aldWorkspace *ws, int ac, char **av)

{
  struct genericList *node;
  struct stepDisplay *sptr;

  node = ws->stepDisplayList;

  Print(ws,
        P_COMMAND,
        "Num   Start      NumBytes   ElSize   Output");

  while (node)
  {
    sptr = (struct stepDisplay *) node->ptr;

    Print(ws,
          P_COMMAND,
          "%-5u 0x%08X %-10ld %-8ld %c",
          sptr->number,
          sptr->startaddr,
          sptr->numbytes,
          sptr->elsize,
          sptr->output);

    node = node->next;
  } /* while (node) */

  return (1);
} /* c_ldisplay() */
