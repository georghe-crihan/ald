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
 * $Id: print.h,v 1.1.1.1 2004/04/26 00:41:12 pa33 Exp $
 */

#ifndef INCLUDED_print_h
#define INCLUDED_print_h

#ifndef INCLUDED_stdio_h
#include <stdio.h>         /* FILE * */
#define INCLUDED_stdio_h
#endif

#ifndef INCLUDED_stdarg_h
#include <stdarg.h>
#define INCLUDED_stdarg_h
#endif

#ifndef INCLUDED_alddefs_h
#include "alddefs.h"       /* MAXLINE */
#define INCLUDED_alddefs_h
#endif

struct printWorkspace
{
  int PausePrint;              /* print bursts will be paused after each pageful */
  int PrintBurst;              /* set if print burst in progress */
  unsigned long PrintLineCnt;  /* number of printed lines during burst */
  FILE *file_p;                /* alternate output file (from "set output") */
  char *filename;              /* filename corresponding to file_p */
};

#define P_DEBUG       (1 << 0) /* DebugFrame */
#define P_DISASSEMBLY (1 << 1) /* DisassemblyFrame */
#define P_COMMAND     (1 << 2) /* CommandOutputFrame */
#define P_ERROR       (1 << 3) /* error output window */
#define P_MEMORY      (1 << 4) /* memory output window */
#define P_REGISTER    (1 << 5) /* register output window */
#define P_OUTPUT      (1 << 6) /* ProcessOutputFrame */

/*
 * Prototypes
 */

struct aldWorkspace;

struct printWorkspace *initPrint();
void termPrint(struct printWorkspace *ws);

void startPrintBurst(struct printWorkspace *ws);
void endPrintBurst(struct printWorkspace *ws);
void Print(struct aldWorkspace *main_p, int flags, const char *format, ...);
void RawPrint(struct aldWorkspace *main_p, int flags, const char *format, ...);
void PrintWindow(struct aldWorkspace *main_p, int raw,
                 const char *format, va_list args);

#endif /* INCLUDED_print_h */
