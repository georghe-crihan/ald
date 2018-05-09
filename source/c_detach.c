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
 * $Id: c_detach.c,v 1.1.1.1 2004/04/26 00:40:45 pa33 Exp $
 */

#include <errno.h>
#include <string.h>

#include "main.h"
#include "msg.h"
#include "print.h"

#include "libDebug.h"

/*
c_detach()
  Detach debugger from current process

Format for this command:
  detach

Return: 0 upon failure
        1 upon success
*/

int
c_detach(struct aldWorkspace *ws, int ac, char **av)

{
  int dret;

  dret = detachDebug(ws->debugWorkspace_p);
  switch (dret)
  {
    case 0:
    {
      Print(ws,
            P_ERROR,
            MSG_PTERR,
            strerror(errno));
      return (0);

      break; /* not reached */
    } /* case 0 */

    case -1:
    {
      Print(ws,
            P_ERROR,
            "error: Not currently attached to a process");
      return (0);

      break; /* not reached */
    }

    default:
    {
      Print(ws,
            P_COMMAND,
            "Detached from process id %d",
            dret);
      break;
    }
  }

  awClearAttached(ws);

  return (1);
} /* c_detach() */
