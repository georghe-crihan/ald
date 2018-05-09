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
 * $Id: c_quit.c,v 1.2 2004/04/26 03:39:32 pa33 Exp $
 */

#include "load.h"
#include "main.h"
#include "misc.h"
#include "rc.h"

/*
c_quit()
 Terminate the program

Return: -1
*/

int
c_quit(struct aldWorkspace *ws, int ac, char **av)

{
  /*
   * Save settings to configuration file
   */
  writeRC(ws);

  return (-1);
} /* c_quit() */
