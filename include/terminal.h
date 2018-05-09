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
 * $Id: terminal.h,v 1.1.1.1 2004/04/26 00:41:11 pa33 Exp $
 */

#ifndef INCLUDED_terminal_h
#define INCLUDED_terminal_h

#ifndef INCLUDED_defs_h
#include "defs.h"        /* HAVE_TERMIOS_H */
#define INCLUDED_defs_h
#endif

#if defined(HAVE_TERMIOS_H)
#include <termios.h>
#elif defined(HAVE_TERMIO_H)
#include <termio.h>
#endif

struct ttyState
{
#if defined(HAVE_TERMIOS_H)

  struct termios in;
  struct termios out;
  struct termios err;

#elif defined(HAVE_TERMIO_H)

  struct termio in;
  struct termio out;
  struct termio err;

#endif
};

struct terminalWorkspace
{
  int LinesPerPage;         /* number of lines per page */
  int ColsPerLine;          /* number of columns per line */

  /*
   * Terminal state for the debugger process
   */
  struct ttyState ParentAttributes;

  /*
   * Terminal state for the process we are debugging
   */
  struct ttyState ChildAttributes;
};

/*
 * Prototypes
 */

struct terminalWorkspace *initTerminal();
void termTerminal(struct terminalWorkspace *ws);
int saveTerminal(struct ttyState *state);
int restoreTerminal(struct ttyState *state);

#endif /* INCLUDED_terminal_h */
