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
 * $Id: registers.h,v 1.1.1.1 2004/04/26 00:41:11 pa33 Exp $
 */

#ifndef INCLUDED_registers_h
#define INCLUDED_registers_h

#ifndef INCLUDED_alddefs_h
#include "alddefs.h"        /* MAXLINE */
#define INCLUDED_alddefs_h
#endif

#ifndef INCLUDED_main_h
#include "main.h"
#define INCLUDED_main_h
#endif

/*
 * Argument to displayRegisters() if there is no specific
 * register to display (display all of them)
 */
#define NOREG      (-1)

struct callbackArgs
{
  struct aldWorkspace *main_p;  /* pointer to main workspace */
  int regcount;                 /* number of registers printed to current line */
  char scratch[MAXLINE];        /* scratch buffer */
};

/*
 * Prototypes
 */

void displayRegisters(struct aldWorkspace *ws, int regindex, int compact,
                      unsigned int flgs);

#endif /* INCLUDED_registers_h */
