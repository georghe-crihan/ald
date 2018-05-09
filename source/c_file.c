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
 * $Id: c_file.c,v 1.1.1.1 2004/04/26 00:40:41 pa33 Exp $
 */

#include "callback.h"
#include "command.h"
#include "load.h"
#include "main.h"
#include "print.h"

static int c_file_header(struct aldWorkspace *ws, int ac, char **av);
static int c_file_secinfo(struct aldWorkspace *ws, int ac, char **av);
static int c_file_syminfo(struct aldWorkspace *ws, int ac, char **av);

static struct Command fileCmds[] = {
  { "header", c_file_header, 0 },
  { "secinfo", c_file_secinfo, 0 },
  { "syminfo", c_file_syminfo, 0 },
  { 0, 0, 0 }
};

/*
c_file()
  Configure various settings

Return: 0 upon failure
        1 upon success
*/

int
c_file(struct aldWorkspace *ws, int ac, char **av)

{
  struct Command *cptr;
  unsigned int flags;

  if (ac < 2)
  {
    Print(ws, P_COMMAND, "Syntax: file <header | secinfo | syminfo>");
    return (0);
  }

  flags = 0;
  cptr = FindCommand(fileCmds, av[1], &flags);
  if (cptr)
  {
    /*
     * Call cptr->func to execute command
     */
    (*cptr->funcptr)(ws, ac, av);
  }
  else
  {
    /*
     * They gave us an invalid command
     */
    Print(ws,
          P_COMMAND,
          "%s command: file %s",
          (flags & C_AMBIGUOUS) ? "Ambiguous" : "Unknown",
          av[1]);
  }

  return (1);
} /* c_file() */

/*
c_file_header()
  Display information about the current file's header
*/

static int
c_file_header(struct aldWorkspace *ws, int ac, char **av)

{
  Print(ws,
        P_COMMAND,
        "%s:",
        ws->objectFileName);

  printHeaderOFF(ws->offWorkspace_p,
                 &callbackPrintOFF,
                 (void *) ws);

  return (1);
} /* c_file_header() */

/*
c_file_secinfo()
  Display information about the current file's sections
*/

static int
c_file_secinfo(struct aldWorkspace *ws, int ac, char **av)

{
  char *secname;

  secname = 0;

  if (ac > 2)
    secname = av[2];

  startPrintBurst(ws->printWorkspace_p);

  printSectionInfoOFF(ws->offWorkspace_p,
                      secname,
                      &callbackPrintOFF,
                      (void *) ws);

  endPrintBurst(ws->printWorkspace_p);

  return (1);
} /* c_file_secinfo() */

/*
c_file_syminfo()
  Display information about the current file's symbols, if any
*/

static int
c_file_syminfo(struct aldWorkspace *ws, int ac, char **av)

{
  char *symname;

  symname = 0;

  if (ac > 2)
    symname = av[2];

  startPrintBurst(ws->printWorkspace_p);

  printSymbolsOFF(ws->offWorkspace_p,
                  symname,
                  &callbackPrintOFF,
                  (void *) ws);

  endPrintBurst(ws->printWorkspace_p);

  return (1);
} /* c_file_syminfo() */
