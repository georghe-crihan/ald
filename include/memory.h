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
 * $Id: memory.h,v 1.2 2004/07/21 16:36:06 pa33 Exp $
 */

#ifndef INCLUDED_memory_h
#define INCLUDED_memory_h

#ifndef INCLUDED_main_h
#include "main.h"
#define INCLUDED_main_h
#endif

struct MemFormat
{
  unsigned char delim; /* one of 'x', 'o', 'b', 'd' */
  char *desc;          /* description (ie: octal, hex, etc) */
  char *fmt;           /* format string */
  int epl;             /* number of elements to display per line */
  int cpe;             /* number of characters per element */
};

/*
 * MF_xxx - array indices of the OutputFormats[] array
 */
#define MF_1HEX        0
#define MF_2HEX        1
#define MF_4HEX        2
#define MF_8HEX        3
#define MF_1OCTAL      4
#define MF_2OCTAL      5
#define MF_4OCTAL      6
#define MF_1DECIMAL    7
#define MF_2DECIMAL    8
#define MF_4DECIMAL    9

/*
 * Prototypes
 */
unsigned long GetElementSize(char *str);
void OutputMemory(struct aldWorkspace *ws, unsigned char *buf, unsigned long start,
                  long bytes, long size, unsigned char output);

#endif /* INCLUDED_memory_h */
