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
 * $Id: terminal.c,v 1.1.1.1 2004/04/26 00:40:47 pa33 Exp $
 */

#include "defs.h"

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#ifdef HAVE_TERM_H
#include <term.h>
#endif

#include "misc.h"
#include "print.h"
#include "terminal.h"

#if defined(HAVE_TERMIOS_H)
#include <termios.h>
#elif defined(HAVE_TERMIO_H)
#include <termio.h>
#endif

/*
initTerminal()
  Sets up some variables for our terminal

Return: pointer to new workspace
*/

struct terminalWorkspace *
initTerminal()

{
  struct terminalWorkspace *ws;

  ws = (struct terminalWorkspace *) malloc(sizeof(struct terminalWorkspace));
  if (!ws)
  {
    fprintf(stderr, "initTerminal: malloc failed: %s\n",
      strerror(errno));
    return (0);
  }

  memset(ws, '\0', sizeof(struct terminalWorkspace));

  /*
   * Attempt to determine how many lines/cols are in our terminal.
   * Print() makes use of this information for pause-print etc.
   */

  /*
   * Set up defaults
   */
  ws->LinesPerPage = 25;
  ws->ColsPerLine = 80;

  if (!saveTerminal(&(ws->ParentAttributes)))
  {
    fprintf(stderr, "initTerminal: saveTerminal failed\n");
    termTerminal(ws);
    return (0);
  }

  if (!saveTerminal(&(ws->ChildAttributes)))
  {
    fprintf(stderr, "initTerminal: saveTerminal failed\n");
    termTerminal(ws);
    return (0);
  }

  return (ws);
} /* initTerminal() */

/*
termTerminal()
  Terminate a terminal workspace

Inputs: ws - workspace to terminate
*/

void
termTerminal(struct terminalWorkspace *ws)

{
  if (!ws)
    return;

  free(ws);
} /* termTerminal() */

/*
saveTerminal()
  Save the current state of the terminal into the given variable

Return: 1 if successful, 0 if not
*/

int
saveTerminal(struct ttyState *state)

{
  if (isatty(STDIN_FILENO))
  {
  #if defined(HAVE_TERMIOS_H)

    if (tcgetattr(STDIN_FILENO, &(state->in)) == (-1))
      return (0);

  #elif defined(HAVE_TERMIO_H)

    if (ioctl(STDIN_FILENO, TCGETA, &(state->in)) == (-1))
      return (0);

  #endif
  }

  if (isatty(STDOUT_FILENO))
  {
  #if defined(HAVE_TERMIOS_H)

    if (tcgetattr(STDOUT_FILENO, &(state->out)) == (-1))
      return (0);

  #elif defined(HAVE_TERMIO_H)

    if (ioctl(STDOUT_FILENO, TCGETA, &(state->out)) == (-1))
      return (0);

  #endif
  }

  if (isatty(STDERR_FILENO))
  {
  #if defined(HAVE_TERMIOS_H)

    if (tcgetattr(STDERR_FILENO, &(state->err)) == (-1))
      return (0);

  #elif defined(HAVE_TERMIO_H)

    if (ioctl(STDERR_FILENO, TCGETA, &(state->err)) == (-1))
      return (0);

  #endif
  }

  return (1);
} /* saveTerminal() */

/*
restoreTerminal()
  Restore terminal state

Inputs: state - state to restore

Return: 1 if successful, 0 if not
*/

int
restoreTerminal(struct ttyState *state)

{
  if (isatty(STDIN_FILENO))
  {
  #if defined(HAVE_TERMIOS_H)

    if (tcsetattr(STDIN_FILENO, TCSANOW, &(state->in)) == (-1))
      return (0);

  #elif defined(HAVE_TERMIO_H)

    if (ioctl(STDIN_FILENO, TCSETA, &(state->in)) == (-1))
      return (0);

  #endif
  }

  if (isatty(STDOUT_FILENO))
  {
  #if defined(HAVE_TERMIOS_H)

    if (tcsetattr(STDOUT_FILENO, TCSANOW, &(state->out)) == (-1))
      return (0);

  #elif defined(HAVE_TERMIO_H)

    if (ioctl(STDOUT_FILENO, TCSETA, &(state->out)) == (-1))
      return (0);

  #endif
  }

  if (isatty(STDERR_FILENO))
  {
  #if defined(HAVE_TERMIOS_H)

    if (tcsetattr(STDERR_FILENO, TCSANOW, &(state->err)) == (-1))
      return (0);

  #elif defined(HAVE_TERMIO_H)

    if (ioctl(STDERR_FILENO, TCSETA, &(state->err)) == (-1))
      return (0);

  #endif
  }

  return (1);
} /* restoreTerminal() */

#if 0
/*
SaveParentTerminalState()
  Save the attributes of the terminal into the variable
ParentAttributes

Return: 1 if successful
        0 if not
*/

void
SaveParentTerminalState()

{
  if (!saveTerminal(&ParentAttributes))
  {
    Print(P_COMMAND,
      "Error saving parent's terminal state: %s",
      strerror(errno));
    exit(1);
  }
} /* SaveParentTerminalState() */

/*
RestoreParentTerminalState()
  Restore the original state of the terminal, using values from
the variable ParentAttributes

Return: 1 if successful
        0 if not
*/

void
RestoreParentTerminalState()

{
  if (!RestoreTerminalState(&ParentAttributes))
  {
    Print(P_COMMAND,
      "Error restoring parent's terminal state: %s",
      strerror(errno));
    exit(1);
  }
} /* RestoreParentTerminalState() */

/*
SaveChildTerminalState()
  Save the attributes of the terminal into the variable
ChildAttributes

Return: 1 if successful
        0 if not
*/

void
SaveChildTerminalState()

{
  if (!saveTerminal(&ChildAttributes))
  {
    Print(P_COMMAND,
      "Error saving child's terminal state: %s",
      strerror(errno));
    exit(1);
  }
} /* SaveChildTerminalState() */

/*
RestoreChildTerminalState()
  Restore the original state of the terminal, using values from
the variable ChildAttributes

Return: 1 if successful
        0 if not
*/

void
RestoreChildTerminalState()

{
  if (!RestoreTerminalState(&ChildAttributes))
  {
    Print(P_COMMAND,
      "Error restoring child's terminal state: %s",
      strerror(errno));
    exit(1);
  }
} /* RestoreChildTerminalState() */

#endif /* 0 */
