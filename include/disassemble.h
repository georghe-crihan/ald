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
 * $Id: disassemble.h,v 1.1.1.1 2004/04/26 00:41:12 pa33 Exp $
 */

#ifndef INCLUDED_disassemble_h
#define INCLUDED_disassemble_h

#ifndef INCLUDED_main_h
#include "main.h"        /* struct aldWorkspace */
#define INCLUDED_main_h
#endif

/*
 * Prototypes
 */

long Disassemble(struct aldWorkspace *ws, unsigned char *data,
                 unsigned int address, unsigned int owin);
void DisplayNextInstruction(struct aldWorkspace *ws);

#endif /* INCLUDED_disassemble_h */
