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
 * $Id: help.h,v 1.1.1.1 2004/04/26 00:41:11 pa33 Exp $
 */

#ifndef INCLUDED_help_h
#define INCLUDED_help_h

#ifndef INCLUDED_main_h
#include "main.h"
#define INCLUDED_main_h
#endif

struct HelpCmd
{
  char *name;          /* command name */
  char *desc;          /* short description */
  char *usage;         /* command usage */
};

/*
 * Prototypes
 */

void GiveHelp(struct aldWorkspace *ws, int ac, char **av);

#endif /* INCLUDED_help_h */
