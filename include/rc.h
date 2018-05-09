/*
 * Assembly Language Debugger
 *
 * Copyright (C) 2000-2003 Patrick Alken
 * This program comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: rc.h,v 1.1.1.1 2004/04/26 00:41:11 pa33 Exp $
 */

#ifndef INCLUDED_rc_h
#define INCLUDED_rc_h

#ifndef INCLUDED_alddefs_h
#include "alddefs.h"           /* MAXLINE */
#define INCLUDED_alddefs_h
#endif

struct rcWorkspace
{
  char filename[MAXLINE];
};

/*
 * Run commands filename
 */
#define RC_FILENAME       ".aldrc"

#ifndef INCLUDED_main_h
#include "main.h"              /* struct aldWorkspace */
#define INCLUDED_main_h
#endif

/*
 * Prototypes
 */

struct rcWorkspace *initRC();
void termRC(struct rcWorkspace *ws);
int readRC(struct aldWorkspace *ws);
int writeRC(struct aldWorkspace *ws);

#endif /* INCLUDED_rc_h */
