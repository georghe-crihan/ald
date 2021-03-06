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
 * $Id: output.h,v 1.1.1.1 2004/04/26 00:41:12 pa33 Exp $
 */

#ifndef INCLUDED_output_h
#define INCLUDED_output_h

/*
 * Prototypes
 */

int BoolPrompt(char *prompt);
unsigned long NumPrompt(char *prompt, int *err);

#endif /* INCLUDED_output_h */
