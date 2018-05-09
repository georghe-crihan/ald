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
 * $Id: c_load.c,v 1.1.1.1 2004/04/26 00:40:41 pa33 Exp $
 */

#include "load.h"
#include "main.h"
#include "print.h"

#include "libDebug.h"

/*
c_load()
 Load a new file

Return: 0 upon failure
        1 upon success
*/

int
c_load(struct aldWorkspace *ws, int ac, char **av)

{
  if (ac < 2)
  {
    Print(ws, P_COMMAND, "Syntax: load <filename>");
    return (0);
  }

  loadFile(ws, av[1]);

  startDebug(ws->debugWorkspace_p, av[1], 0);

  awSetFileLoaded(ws);

  return (1);
} /* c_load() */
