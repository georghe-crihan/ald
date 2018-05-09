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
 * $Id: sub-x86.h,v 1.2 2004/09/11 05:17:15 pa33 Exp $
 */

#ifndef INCLUDED_sub_x86_h
#define INCLUDED_sub_x86_h

struct OpSub
{
  unsigned int byte;  /* first byte of opcode */
  int digit;          /* ModR/M digit or -1 */
  unsigned int oplen; /* total opcode length */
};

/*
 * Prototypes
 */
int IsSubroutine(unsigned char *buf);

#endif /* INCLUDED_sub_x86_h */
