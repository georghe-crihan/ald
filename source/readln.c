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
 * $Id: readln.c,v 1.2 2004/04/26 03:39:32 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>

#include "alddefs.h"
#include "command.h"
#include "defs.h"
#include "misc.h"
#include "print.h"
#include "rc.h"

#ifdef HAVE_READLINE_READLINE_H
#include <readline/readline.h>
#endif

#ifdef HAVE_READLINE_HISTORY_H

#include <readline/history.h>

#else

extern void add_history();

#endif /* !HAVE_READLINE_HISTORY_H */

/*
 * libString includes
 */
#include "Strn.h"

#ifndef HAVE_READLINE

/*
DisplayPrompt()
  Display command prompt

Inputs: ws - ald workspace
*/

static void
DisplayPrompt(struct aldWorkspace *ws)

{
  fprintf(stdout,
    "%s",
    ws->commandWorkspace_p->CmdPrompt);
} /* DisplayPrompt() */

#endif /* !HAVE_READLINE */

/*
ReadLine()
  Read a line from stdin and return a pointer to it. FreeLine()
must be called when the calling function is done with the buffer.

Inputs: ws - ald workspace
*/

char *
ReadLine(struct aldWorkspace *ws)

{
  char *ret;
#ifndef HAVE_READLINE
  char buffer[MAXLINE];
#endif

#ifdef HAVE_READLINE

  ret = readline(ws->commandWorkspace_p->CmdPrompt);

  if (!ret)
  {
    /*
     * EOF occurred (possibly ^D)
     */
    writeRC(ws);
    exit(1);
  }
  else if (*ret != '\0')
    add_history(ret);

#else

  DisplayPrompt(ws);

  ret = fgets(buffer, MAXLINE, stdin);
  if (ret)
    ret = Strdup(buffer);
  else
  {
    /*
     * Error occured - probably EOF (^D)
     */
    writeRC(ws);
    exit(1);
  }

#endif /* !HAVE_READLINE */

  return (ret);
} /* ReadLine() */

/*
FreeLine()
  Frees the memory used by 'buf'
*/

void
FreeLine(char *buf)

{
  if (buf)
    free(buf);
} /* FreeLine() */
