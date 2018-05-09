/*
 * libDebug
 *
 * Copyright (C) 2000 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: bsd-x86.h,v 1.1.1.1 2004/04/26 00:41:04 pa33 Exp $
 */

#ifndef INCLUDED_bsd_x86_h
#define INCLUDED_bsd_x86_h

#ifndef INCLUDED_libDebug_h
#include "libDebug.h"
#define INCLUDED_libDebug_h
#endif

/*
 * Prototypes
 */

struct debugWorkspace;

int x86initRegistersDebug(struct debugWorkspace *ws);
unsigned long x86getCurrentInstruction(struct debugWorkspace *ws, int *err);
int x86setCurrentInstruction(struct debugWorkspace *ws, unsigned long address);
int x86getRegistersDebug(struct debugWorkspace *ws);
int x86readFPUDebug(struct debugWorkspace *ws, struct x86fpuInfo *fpuState);
int x86writeRegisterDebug(struct debugWorkspace *ws, struct x86RegInfo *rptr,
                          struct x86RegValue *regVal);

#endif /* INCLUDED_bsd_x86_h */
