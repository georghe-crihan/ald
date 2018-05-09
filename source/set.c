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
 * $Id: set.c,v 1.1.1.1 2004/04/26 00:40:42 pa33 Exp $
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "alddefs.h"
#include "command.h"
#include "load.h"
#include "main.h"
#include "misc.h"
#include "msg.h"
#include "print.h"
#include "set.h"

#include "libDebug.h"

/*
 * libString includes
 */
#include "Strn.h"

static int setArgs(struct aldWorkspace *ws, int ac, char **av,
                   unsigned int pwin, char *str);
static int setDisasmShowSyms(struct aldWorkspace *ws, int ac, char **av,
                             unsigned int pwin, char *str);
static int setEntryPoint(struct aldWorkspace *ws, int ac, char **av,
                         unsigned int pwin, char *str);
static int setFileOffset(struct aldWorkspace *ws, int ac, char **av,
                         unsigned int pwin, char *str);
static int setOutput(struct aldWorkspace *ws, int ac, char **av, unsigned int pwin,
                     char *str);
static int setPausePrint(struct aldWorkspace *ws, int ac, char **av, unsigned int pwin,
                         char *str);
static int setPrompt(struct aldWorkspace *ws, int ac, char **av, unsigned int pwin,
                     char *str);
static int setStepDisplayRegs(struct aldWorkspace *ws, int ac, char **av,
                               unsigned int pwin, char *str);
static int setStepDisplayFpRegs(struct aldWorkspace *ws, int ac, char **av,
                                 unsigned int pwin, char *str);
static int setStepDisplayMmxRegs(struct aldWorkspace *ws, int ac, char **av,
                                  unsigned int pwin, char *str);

static struct Command setCmds[] = {
  { "args", setArgs, 0 },
  { "disasm-show-syms", setDisasmShowSyms, 0 },
  { "entry-point", setEntryPoint, 0 },
  { "file-offset", setFileOffset, 0 },
  { "offset", setFileOffset, C_ALIAS },
  { "output", setOutput, 0 },
  { "pause-print", setPausePrint, 0 },
  { "prompt", setPrompt, 0 },
  { "step-display-regs", setStepDisplayRegs, 0 },
  { "step-display-fpregs", setStepDisplayFpRegs, 0 },
  { "step-display-mmxregs", setStepDisplayMmxRegs, 0 },
  { 0, 0, 0 }
};

static char *setCmdsSyntax[] = {
  "",                                     /* SETSYN_ARGS */
  "set disasm-show-syms <on | off>",      /* SETSYN_DISASM_SHOW_SYMS */
  "set entry-point <address>",            /* SETSYN_ENTRY */
  "set file-offset <address>",            /* SETSYN_OFFSET */
  "set output <filename>",                /* SETSYN_OUTPUT */
  "set pause-print <on | off>",           /* SETSYN_PAUSEPRINT */
  "set prompt <new prompt>",              /* SETSYN_PROMPT */
  "set step-display-regs <on | off>",     /* SETSYN_STEP_DISP_REGS */
  "set step-display-fpregs <on | off>",   /* SETSYN_STEP_DISP_FPREGS */
  "set step-display-mmxregs <on | off>"   /* SETSYN_STEP_DISP_MMXREGS */
};

/*
DisplaySettings()
  Output a list of all settings and their values
*/

void
DisplaySettings(struct aldWorkspace *ws)

{
  struct Command *cptr;
  char buf[MAXLINE];

  for (cptr = setCmds; cptr->cmd != 0; ++cptr)
  {
    if (cptr->flags & C_ALIAS)
      continue; /* don't display aliases */

    RawPrint(ws, P_COMMAND, "%-30s", cptr->cmd);

    (*cptr->funcptr)(ws, 0, 0, P_COMMAND, buf);
    RawPrint(ws, P_COMMAND, "%s", buf);

    RawPrint(ws, P_COMMAND, "\n");
  }
} /* DisplaySettings() */

/*
FindSetCommand()
  Search for a set command name in the array 'setCmds'
*/

struct Command *
FindSetCommand(char *name, unsigned int *flags)

{
  return (FindCommand(setCmds, name, flags));
} /* FindSetCommand() */

/*******************************************************
 *                 INTERNAL ROUTINES                   *
 *******************************************************/

/*
setArgs()
  Set the runtime arguments for the debugged process

Return: 0 upon failure (error goes in str)
        1 upon syntax error (syntax goes in str)
        2 upon success
*/

static int
setArgs(struct aldWorkspace *ws, int ac, char **av, unsigned int pwin,
        char *str)

{
  char argstr[MAXLINE];
  char *tmp;
  int ii;
  int len;

  if (pwin != 0)
  {
    tmp = getArgsDebug(ws->debugWorkspace_p);
    Sprintf(str, "%s", tmp ? tmp : "none");
    return (2);
  }

  if (ac < 3)
  {
    /*
     * No arguments means unset previous args
     */
    setArgsDebug(ws->debugWorkspace_p, 0);
    return (2);
  }

  len = sizeof(argstr);

  tmp = argstr;
  for (ii = 2; ii < ac; ++ii)
  {
    tmp += Snprintf(tmp, len, "%s ", av[ii]);
    len = sizeof(argstr) - (int) (tmp - argstr);
  }

  setArgsDebug(ws->debugWorkspace_p, argstr);

  return (2);
} /* setArgs() */

/*
setDisasmShowSyms()
  Show symbols in disassembled output

Return: 0 upon failure (error goes in str)
        1 upon syntax error (syntax goes in str)
        2 upon success
*/

static int
setDisasmShowSyms(struct aldWorkspace *ws, int ac, char **av, unsigned int pwin,
                  char *str)

{
  if (pwin != 0)
  {
    Sprintf(str,
            "%s",
            IsSetDisasmShowSyms(ws) ? "on" : "off");
    return (2);
  }

  if (ac < 3)
  {
    Sprintf(str, "%s", setCmdsSyntax[SETSYN_DISASM_SHOW_SYMS]);
    return (1);
  }

  if (StrToBool(av[2]))
    SetDisasmShowSyms(ws);
  else
    UnsetDisasmShowSyms(ws);

  return (2);
} /* setDisasmShowSyms() */

/*
setEntryPoint()
  Sets the entry point for the program being debugged

Return: 0 upon failure (error goes in str)
        1 upon syntax error (syntax goes in str)
        2 upon success
*/

static int
setEntryPoint(struct aldWorkspace *ws, int ac, char **av, unsigned int pwin,
              char *str)

{
  long address;

  if (pwin != 0)
  {
    Sprintf(str,
            "0x%08X (0x%08X)",
            ws->entryPoint,
            ws->virtualEntryPoint);
    return (2);
  }

  if (ac < 3)
  {
    Sprintf(str, "%s", setCmdsSyntax[SETSYN_ENTRY]);
    return (1);
  }

  address = strtol(av[2], 0, 16);

  ws->entryPoint = (unsigned int) address;
  ws->virtualEntryPoint = (unsigned int) address + ws->virtualFileAddress;

  return (2);
} /* setEntryPoint() */

/*
setFileOffset()
  Sets the offset from the beginning of the file being debugged.
Commands such as "disassemble" will use this value as their
starting point

Return: 0 upon failure (error goes in str)
        1 upon syntax error (syntax goes in str)
        2 upon success
*/

static int
setFileOffset(struct aldWorkspace *ws, int ac, char **av, unsigned int pwin,
              char *str)

{
  long address;

  if (pwin != 0)
  {
    Sprintf(str,
            "0x%08X (0x%08X)",
            ws->objectFileOffset,
            ws->virtualObjectFileOffset);
    return (2);
  }

  if (ac < 3)
  {
    Sprintf(str, "%s", setCmdsSyntax[SETSYN_OFFSET]);
    return (1);
  }

  address = strtol(av[2], 0, 16);

  ws->objectFileOffset = (unsigned int) address;
  ws->virtualObjectFileOffset = (unsigned int) address + ws->virtualFileAddress;

  return (2);
} /* setFileOffset() */

/*
setOutput()
  Sets the path of a file to write the window's contents to, in addition to
writing to the window

Return: 0 upon failure (error goes in str)
        1 upon syntax error (syntax goes in str)
        2 upon success
*/

static int
setOutput(struct aldWorkspace *ws, int ac, char **av, unsigned int pwin,
          char *str)

{
  FILE *fp;

  if (pwin != 0)
  {
    Sprintf(str,
            "%s",
            ws->printWorkspace_p->filename ? ws->printWorkspace_p->filename : "none");
    return (2);
  }

  if (ac < 3)
  {
    Sprintf(str, "%s", setCmdsSyntax[SETSYN_OUTPUT]);
    return (1);
  }

  fp = fopen(av[2], "w");
  if (!fp)
  {
    Sprintf(str,
            "Unable to open file %s: %s",
            av[2],
            strerror(errno));
    return (0);
  }

  ws->printWorkspace_p->file_p = fp;
  ws->printWorkspace_p->filename = Strdup(av[2]);

  return (2);
} /* setOutput() */

/*
setPausePrint()
  Enables/Disables pausing of print bursts for commands which output
a lot of information

Return: 0 upon failure (error goes in str)
        1 upon syntax error (syntax goes in str)
        2 upon success
*/

static int
setPausePrint(struct aldWorkspace *ws, int ac, char **av, unsigned int pwin,
              char *str)

{
  if (pwin != 0)
  {
    Sprintf(str,
            "%s",
            ws->printWorkspace_p->PausePrint ? "on" : "off");
    return (2);
  }

  if (ac < 3)
  {
    Sprintf(str, "%s", setCmdsSyntax[SETSYN_PAUSEPRINT]);
    return (1);
  }

  ws->printWorkspace_p->PausePrint = StrToBool(av[2]);
  
  return (2);
} /* setPausePrint() */

/*
setPrompt()
  Set the command prompt string

Return: 0 upon failure (error goes in str)
        1 upon syntax error (syntax goes in str)
        2 upon success
*/

static int
setPrompt(struct aldWorkspace *ws, int ac, char **av, unsigned int pwin,
          char *str)

{
  if (pwin != 0)
  {
    Sprintf(str,
            "\"%s\"",
            ws->commandWorkspace_p->CmdPrompt);
    return (2);
  }

  if (ac < 3)
  {
    Sprintf(str, "%s", setCmdsSyntax[SETSYN_PROMPT]);
    return (1);
  }

  free(ws->commandWorkspace_p->CmdPrompt);
  ws->commandWorkspace_p->CmdPrompt = Strdup(av[2]);

  return (2);
} /* setPrompt() */

/*
setStepDisplayRegs()
  Display register contents after a single step

Return: 0 upon failure (error goes in str)
        1 upon syntax error (syntax goes in str)
        2 upon success
*/

static int
setStepDisplayRegs(struct aldWorkspace *ws, int ac, char **av, unsigned int pwin,
                   char *str)

{
  if (pwin != 0)
  {
    Sprintf(str,
            "%s",
            IsSetStepDisplayRegs(ws) ? "on" : "off");
    return (2);
  }

  if (ac < 3)
  {
    Sprintf(str, "%s", setCmdsSyntax[SETSYN_STEP_DISP_REGS]);
    return (1);
  }

  if (StrToBool(av[2]))
  {
    SetStepDisplayRegs(ws);
    ws->stepDisplayFlags |= DB_REGFL_DISPLAY_GENERAL;
  }
  else
  {
    UnsetStepDisplayRegs(ws);
    ws->stepDisplayFlags &= ~DB_REGFL_DISPLAY_GENERAL;
  }

  return (2);
} /* setStepDisplayRegs() */

/*
setStepDisplayFpRegs()
  Display floating point register contents after a single step

Return: 0 upon failure (error goes in str)
        1 upon syntax error (syntax goes in str)
        2 upon success
*/

static int
setStepDisplayFpRegs(struct aldWorkspace *ws, int ac, char **av, unsigned int pwin,
                     char *str)

{
  if (pwin != 0)
  {
    Sprintf(str,
            "%s",
            IsSetStepDisplayFpRegs(ws) ? "on" : "off");
    return (2);
  }

  if (ac < 3)
  {
    Sprintf(str, "%s", setCmdsSyntax[SETSYN_STEP_DISP_FPREGS]);
    return (1);
  }

  if (StrToBool(av[2]))
  {
    SetStepDisplayFpRegs(ws);
    ws->stepDisplayFlags |= DB_REGFL_DISPLAY_FPREGS;
  }
  else
  {
    UnsetStepDisplayFpRegs(ws);
    ws->stepDisplayFlags &= ~DB_REGFL_DISPLAY_FPREGS;
  }

  return (2);
} /* setStepDisplayFpRegs() */

/*
setStepDisplayMmxRegs()
  Display mmx register contents after a single step

Return: 0 upon failure (error goes in str)
        1 upon syntax error (syntax goes in str)
        2 upon success
*/

static int
setStepDisplayMmxRegs(struct aldWorkspace *ws, int ac, char **av, unsigned int pwin,
                      char *str)

{
  if (pwin != 0)
  {
    Sprintf(str,
            "%s",
            IsSetStepDisplayMmxRegs(ws) ? "on" : "off");
    return (2);
  }

  if (ac < 3)
  {
    Sprintf(str, "%s", setCmdsSyntax[SETSYN_STEP_DISP_MMXREGS]);
    return (1);
  }

  if (StrToBool(av[2]))
  {
    SetStepDisplayMmxRegs(ws);
    ws->stepDisplayFlags |= DB_REGFL_DISPLAY_MMXREGS;
  }
  else
  {
    UnsetStepDisplayMmxRegs(ws);
    ws->stepDisplayFlags &= ~DB_REGFL_DISPLAY_MMXREGS;
  }

  return (2);
} /* setStepDisplayMmxRegs() */
