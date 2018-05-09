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
 * $Id: print.c,v 1.1.1.1 2004/04/26 00:40:51 pa33 Exp $
 */

#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>

#include "alddefs.h"
#include "command.h"
#include "defs.h"
#include "main.h"
#include "print.h"
#include "terminal.h"

/*
 * libString includes
 */
#include "Strn.h"

/*
initPrint()
  Initialize a print workspace

Return: pointer to print workspace
*/

struct printWorkspace *
initPrint()

{
  struct printWorkspace *ws;

  ws = (struct printWorkspace *) malloc(sizeof(struct printWorkspace));
  if (!ws)
  {
    fprintf(stderr, "initPrint: malloc failed: %s\n",
      strerror(errno));
    return (0);
  }

  memset(ws, '\0', sizeof(struct printWorkspace));

  ws->PrintBurst = 0;
  ws->PrintLineCnt = 0;
  ws->PausePrint = 1;
  ws->file_p = 0;
  ws->filename = 0;

  return (ws);
} /* initPrint() */

/*
termPrint()
  Terminate a print workspace

Inputs: ws - print workspace

Return: none
*/

void
termPrint(struct printWorkspace *ws)

{
  if (!ws)
    return;

  if (ws->file_p)
    fclose(ws->file_p);

  if (ws->filename)
    free(ws->filename);

  free(ws);
} /* termPrint() */

/*
startPrintBurst()
  This function should be called when we are about to print a lot
of lines of information. It will set up the necessary variables to
pause the printing when a pageful of information has been printed,
so the user can decide whether to continue or stop.
*/

void
startPrintBurst(struct printWorkspace *ws)

{
  if (ws->PausePrint)
  {
    ws->PrintBurst = 1;
    ws->PrintLineCnt = 0;
  }
} /* startPrintBurst() */

/*
endPrintBurst()
  This function should be called after the print burst has completed.
*/

void
endPrintBurst(struct printWorkspace *ws)

{
  ws->PrintBurst = 0;
} /* endPrintBurst() */

/*
Print()
 Print the specified string to the appropriate window

Inputs: main_p - main workspace
        flags  - for curses mode, to specify what window to print to
        format - formatted string to print

NOTE: All routines which print to the output windows
      (OutputWindow1 and OutputWindow2) *MUST* use this routine
      so the window buffers are updated correctly.
*/

void
Print(struct aldWorkspace *main_p, int flags, const char *format, ...)

{
  va_list args;

  va_start(args, format);

  PrintWindow(main_p, 0, format, args);

  va_end(args);
} /* Print() */

/*
RawPrint()
  Similar to Print(), except do not print \n characters on the
end of the string
*/

void
RawPrint(struct aldWorkspace *main_p, int flags, const char *format, ...)

{
  va_list args;

  va_start(args, format);

  PrintWindow(main_p, 1, format, args);

  va_end(args);
} /* RawPrint() */

/*
PrintWindow()

Inputs: main_p - main workspace
        raw    - to specify whether to add a \n to the string
        format - string to print
        args   - list of args

Return: none
*/

void
PrintWindow(struct aldWorkspace *main_p, int raw,
            const char *format, va_list args)

{
  struct printWorkspace *printWorkspace_p = main_p->printWorkspace_p;
  char rawbuf[MAXLINE]; /* raw buffer (format + args) */
  int rawlen;           /* length of raw buffer */

/*  rawlen = vsprintf(rawbuf, format, args); */
  rawlen = vSnprintf(rawbuf, sizeof(rawbuf), (char *) format, args);

  /*
   * We are in console mode - just print it to stdout
   */
  fwrite(rawbuf, sizeof(char), rawlen, stdout);
  if (!raw)
    fputc((unsigned char) '\n', stdout);
  else
    fflush(stdout);

  if (printWorkspace_p->file_p)
  {
    fwrite(rawbuf, sizeof(char), rawlen, printWorkspace_p->file_p);
    if (!raw)
      fputc((unsigned char) '\n', printWorkspace_p->file_p);
    else
      fflush(printWorkspace_p->file_p);
  }

  if (printWorkspace_p->PrintBurst)
  {
    if (raw)
    {
      if (strchr(rawbuf, '\n'))
        ++(printWorkspace_p->PrintLineCnt);
    }
    else
      ++(printWorkspace_p->PrintLineCnt);

    if (printWorkspace_p->PrintLineCnt ==
        (unsigned long) (main_p->terminalWorkspace_p->LinesPerPage - 1))
    {
      char str[MAXLINE];

      /*
       * We have filled up the screen, so pause and let the user
       * hit a key to continue
       */
      fprintf(stdout, "Hit <return> to continue, or <q> to quit");

      fgets(str, MAXLINE, stdin);
      if (*str == 'q')
      {
        /*
         * They want to stop printing - cleanup and simulate a SIGINT
         */
        printWorkspace_p->PrintBurst = 0;
        longjmp(main_p->commandWorkspace_p->CmdParserEnv, SIGINT);
      }
      else
      {
        /*
         * They want to continue printing
         */
        printWorkspace_p->PrintLineCnt = 0;
      }
    }
  } /* if (printWorkspace_p->PrintBurst) */
} /* PrintWindow() */
