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
 * $Id: c_lbreak.c,v 1.1.1.1 2004/04/26 00:40:49 pa33 Exp $
 */

#include <string.h>

#include "main.h"
#include "print.h"

#include "libDebug.h"
#include "libOFF.h"

/*
 * libString includes
 */
#include "Strn.h"

/*
c_lbreak()
  List breakpoints

Return: 0 upon failure
        1 upon success
*/

int
c_lbreak(struct aldWorkspace *ws, int ac, char **av)

{
  struct Breakpoint *bptr;
  char istr[MAXLINE];
  char sstr[MAXLINE];
  struct offSymbolInfo symInfo;
  int sret;

  /*
   * Breakpoints are stored in reverse numerical order, so
   * advance to the end and work backwards
   */
  bptr = ws->debugWorkspace_p->breakpoints;
  while (bptr)
  {
    if (!bptr->next)
      break;
    bptr = bptr->next;
  }

  if (bptr)
  {
    Print(ws,
          P_COMMAND,
          "%-03s   %-10s   %-07s   %-10s   %-12s %-12s",
          "Num",
          "Type",
          "Enabled",
          "Address",
          "IgnoreCount",
          "HitCount");

    while (bptr)
    {
      if (bptr->ignorecnt)
        Sprintf(istr, "%-12d", bptr->ignorecnt);
      else
        strcpy(istr, "none");

      sret = findSymbolOFF(ws->offWorkspace_p,
                           0,
                           bptr->address,
                           &symInfo);
      if (sret)
        Sprintf(sstr, "(%s+0x%x)", symInfo.name, symInfo.offset);
      else
        *sstr = '\0';

      Print(ws,
            P_COMMAND,
            "%-03d   %-10s   %-07s   0x%08lX   %-12s %-08d %s",
            bptr->number,
            "Breakpoint",
            (bptr->flags & BK_ENABLED) ? "y" : "n",
            bptr->address,
            istr,
            bptr->hitcnt,
            sstr);

      bptr = bptr->prev;
    }
  } /* if (bptr) */
  else
    Print(ws, P_COMMAND, "No breakpoints or watchpoints set");

  return (1);
} /* c_lbreak() */
