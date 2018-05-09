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
 * $Id: c_unload.c,v 1.1.1.1 2004/04/26 00:40:49 pa33 Exp $
 */

#include "load.h"
#include "main.h"
#include "misc.h"
#include "print.h"

/*
c_unload()
  Unload current file

Return: 0 upon failure
        1 upon success
*/

int
c_unload(struct aldWorkspace *ws, int ac, char **av)

{
  unloadFile(ws);
  endProcess(ws);

  return (1);
} /* c_unload() */
