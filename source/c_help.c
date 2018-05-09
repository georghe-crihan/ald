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
 * $Id: c_help.c,v 1.1.1.1 2004/04/26 00:40:41 pa33 Exp $
 */

#include "help.h"
#include "main.h"

/*
c_help()
 Give user some help

Return: 0 upon failure
        1 upon success
*/

int
c_help(struct aldWorkspace *ws, int ac, char **av)

{
  GiveHelp(ws, ac, av);

  return (1);
} /* c_help() */
