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
 * $Id: traceresult.h,v 1.1.1.1 2004/04/26 00:41:11 pa33 Exp $
 */

#ifndef INCLUDED_traceresult_h
#define INCLUDED_traceresult_h

/*
 * Prototypes
 */

struct aldWorkspace;

int analyzeTraceResult(struct aldWorkspace *ws, int result, int data);


#endif /* INCLUDED_traceresult_h */
