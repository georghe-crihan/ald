/*
 * Assembly Language Debugger
 *
 * Copyright (C) 2004 Patrick Alken
 * This program comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: display.h,v 1.3 2004/10/10 05:29:48 pa33 Exp $
 */

#ifndef INCLUDED_display_h
#define INCLUDED_display_h

#ifndef INCLUDED_main_h
#include "main.h"
#define INCLUDED_main_h
#endif

struct stepDisplay
{
  unsigned long startaddr;   /* address to begin memory dump */
  long numbytes;             /* number of bytes to dump */
  long elsize;               /* size of each element */
  unsigned char output;      /* output type */
  unsigned int number;       /* number of this node */
};

/*
 * Prototypes
 */

int addStepDisplay(struct aldWorkspace *ws, unsigned long startaddr,
                   long numbytes, long elsize, unsigned char output);
void doStepDisplay(struct aldWorkspace *ws);
struct genericList *findStepDisplayByNumber(struct aldWorkspace *ws,
                                            unsigned int num);

#endif /* INCLUDED_display_h */
