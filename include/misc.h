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
 * $Id: misc.h,v 1.1.1.1 2004/04/26 00:41:12 pa33 Exp $
 */

#ifndef INCLUDED_misc_h
#define INCLUDED_misc_h

#define YESNO(x)  (((x) == 0) ? "no" : "yes")

#ifndef INCLUDED_main_h
#include "main.h"       /* struct aldWorkspace */
#define INCLUDED_main_h
#endif

/*
 * Prototypes
 */

void endProcess(struct aldWorkspace *ws);
void debug(char *format, ...);
int StrToBool(const char *str);

#endif /* INCLUDED_misc_h */
