/*
 * Assembly Language Debugger
 *
 * Copyright (C) 2000-2003 Patrick Alken
 * This program comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: main.c,v 1.1.1.1 2004/04/26 00:39:48 pa33 Exp $
 *
 * This file contains main() for the gtk graphical interface
 * to ald.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <gtk/gtk.h>

#if 0

#include "alddefs.h"
#include "command.h"
#include "defs.h"
#include "load.h"
#include "main.h"
#include "misc.h"
#include "set.h"
#include "signals.h"
#include "terminal.h"
#include "version.h"
#include "window.h"

#include "libDebug.h"
#include "libDASM.h"
#include "libOFF.h"

/*
 * libString includes
 */
#include "Strn.h"

static int ParseCommandLine(struct aldWorkspace *ws, int ac, char *av[],
                            char **filename);

extern char libDebugVersion[];
extern char libDASMVersion[];
extern char libOFFVersion[];

/*
 * Global: Endian type of machine we are running on
 */
int                  PlatformEndian = 0;

/*
ParseCommandLine()
 Parse command line arguments

Inputs: ws       - workspace
        ac       - argument count
        av       - argument array
        filename - set to a filename if one is given on the command line

Return: 1 upon success
        0 upon failure
*/

static int
ParseCommandLine(struct aldWorkspace *ws, int ac, char *av[], char **filename)

{
  while (--ac)
  {
    if (*av[ac] == '-')
    {
      switch (*(av[ac] + 1))
      {
        /*
         * Give help output
         */
        case 'h':
        {
          fprintf(stdout,
            "Usage: %s [options] [filename]\n\
\n\
  [filename]  : Path to executable file to debug\n\
\n\
Options:\n\
\n\
  -c          : Use curses display (if available)\n\
  -h          : Output this help screen\n\
  -v          : Output version information\n",
            av[0]);

          return (0);

          break; /* not reached */
        } /* case 'h' */

        /*
         * Give version information
         */
        case 'v':
        {
          fprintf(stdout,
            "ald version:       %s\n",
            galdVersion);
          fprintf(stdout,
            "libDebug version:  %s\n",
            libDebugVersion);
          fprintf(stdout,
            "libDASM version:   %s\n",
            libDASMVersion);
          fprintf(stdout,
            "libOFF version:    %s\n",
            libOFFVersion);
          fprintf(stdout,
            "libString version: %s\n",
            libStringVersion);

          return (0);

          break; /* not reached */
        } /* case 'v' */

        /*
         * Use curses
         */
        case 'c':
        {
          ModeCurses = 1;
          break;
        } /* case 'c' */
      }
    }
    else
    {
      /*
       * No "-" switch, must be the filename
       */
      *filename = av[ac];
    }
  }

  if (!ModeCurses)
    ModeConsole = 1;

  return (1);
} /* ParseCommandLine() */

/*
initALD()
  Initialize an ald workspace

Inputs: argc - command line argument count
        argv - command line arguments

Return: pointer to new workspace
*/

struct aldWorkspace *
initALD(int argc, char *argv[])

{
  struct aldWorkspace *ws;
  char *filename;
  union
  {
    long l;
    char c[sizeof(long)];
  } end_u;

  ws = (struct aldWorkspace *) malloc(sizeof(struct aldWorkspace));
  if (!ws)
  {
    fprintf(stderr, "initALD: malloc failed: %s\n", strerror(errno));
    return (0);
  }

  memset(ws, '\0', sizeof(struct aldWorkspace));

  ws->filename = 0;

  ModeConsole = 0;
  ModeCurses = 0;

  /*
   * Determine the endian type of this platform
   */
  end_u.l = 1;
  if (end_u.c[sizeof(long) - 1] == 1)
    PlatformEndian = ENDIANTYPE_BIG;
  else
    PlatformEndian = ENDIANTYPE_LITTLE;

  filename = 0;
  if (!ParseCommandLine(ws, argc, argv, &filename))
  {
    /*
     * No error message needed
     */
    termALD(ws);
    return (0);
  }

  /*
   * Setup signal stuff
   */
  SetupSignals();

  ws->commandWorkspace_p = initCommand();
  if (!ws->commandWorkspace_p)
  {
    termALD(ws);
    return (0);
  }

  /*
   * Initialize print workspace
   */
  ws->printWorkspace_p = initPrint();
  if (!ws->printWorkspace_p)
  {
    termALD(ws);
    return (0);
  }

  /*
   * Initialize run commands workspace: if this fails it probably
   * cannot find the home directory so it is not a fatal error.
   */
  ws->rcWorkspace_p = initRC();

  /*
   * Initialize terminal workspace
   */
  ws->terminalWorkspace_p = initTerminal();
  if (!ws->terminalWorkspace_p)
  {
    termALD(ws);
    return (0);
  }

  /*
   * Initialize debug workspace
   */
  ws->debugWorkspace_p = initDebug();
  if (!ws->debugWorkspace_p)
  {
    termALD(ws);
    return (0);
  }

  /*
   * Initialize disasm workspace: default to 16 bit mode
   */
  ws->disasmWorkspace_p = initDisasm(DA_16BITMODE);
  if (!ws->disasmWorkspace_p)
  {
    termALD(ws);
    return (0);
  }

  /*
   * Initialize OFF workspace
   */
  ws->offWorkspace_p = initOFF();
  if (!ws->offWorkspace_p)
  {
    termALD(ws);
    return (0);
  }

  if (ModeCurses)
  {
  #ifdef USE_CURSES

    fprintf(stderr, "ncurses support is currently disabled until a future release\n");
    exit(1);

#if 0
    if (!InitWindows())
      exit(1);
#endif

  #else

    fprintf(stderr,
      "This binary was compiled without ncurses support\n");

    termALD(ws);
    return (0);

  #endif /* !USE_CURSES */
  }

  if (filename)
    ws->filename = filename;

  /*
   * Default settings
   */

  SetDisasmShowSyms(ws);

  ws->stepDisplayFlags = DB_REGFL_DISPLAY_GENERAL;

  SetStepDisplayRegs(ws);

  /*
   * Disassembler settings: default to 16 bit mode
   */
  ws->nextInstruction = 0;
  ws->currentSectionStart = 0;

  return (ws);
} /* initALD() */

/*
termALD()
  Terminate an ald workspace

Inputs: ws - workspace to terminate
*/

void
termALD(struct aldWorkspace *ws)

{
  if (!ws)
    return;

  if (awIsAttached(ws))
  {
    int dret;

    if ((dret = detachDebug(ws->debugWorkspace_p)) > 0)
      fprintf(stderr, "Detached from process id %d\n", dret);
  }

  /*
   * Unload current file if any
   */
  if (awIsFileLoaded(ws))
    unloadFile(ws);

  if (ws->commandWorkspace_p)
    termCommand(ws->commandWorkspace_p);

  if (ws->printWorkspace_p)
    termPrint(ws->printWorkspace_p);

  if (ws->rcWorkspace_p)
    termRC(ws->rcWorkspace_p);

  if (ws->terminalWorkspace_p)
    termTerminal(ws->terminalWorkspace_p);

  if (ws->debugWorkspace_p)
    termDebug(ws->debugWorkspace_p);

  if (ws->disasmWorkspace_p)
    termDisasm(ws->disasmWorkspace_p);

  if (ws->offWorkspace_p)
    termOFF(ws->offWorkspace_p);

  free(ws);
} /* termALD() */

/*
procALD()
  Start everything up

Return: 0 upon fatal error, otherwise will never return
*/

int
procALD(struct aldWorkspace *ws)

{
  /*
   * Start processing commands
   */
  if (!procCommand(ws))
    return (0);

  /*
   * We will never get here
   */
  return (1);
} /* procALD() */

#endif /* 0 */

struct aldWorkspace *mainWorkspace_p;

int
main(int argc, char *argv[])

{
#if 0
  fprintf(stdout, "Assembly Language Debugger %s\n", galdVersion);
  fprintf(stdout, "Copyright (C) 2000-2003 Patrick Alken\n\n");

  mainWorkspace_p = initALD(argc, argv);
  if (!mainWorkspace_p)
    exit(1);

  /*
   * Load runtime configuration file
   */
  readRC(mainWorkspace_p);

  /*
   * If a filename was specified on the command line, get it
   * ready for debugging
   */
  if (mainWorkspace_p->filename)
  {
    loadFile(mainWorkspace_p, mainWorkspace_p->filename);
    startDebug(mainWorkspace_p->debugWorkspace_p, mainWorkspace_p->filename, ModeCurses);
    awSetFileLoaded(mainWorkspace_p);
  }

  procALD(mainWorkspace_p);

  termALD(mainWorkspace_p);

#endif /* 0 */

  /*
   * If procALD() returns, a fatal error occurred
   */
  return (1);
} /* main() */
