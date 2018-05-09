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
 * $Id: command.h,v 1.4 2004/10/10 05:29:48 pa33 Exp $
 */

#ifndef INCLUDED_command_h
#define INCLUDED_command_h

#ifndef INCLUDED_setjmp_h
#include <setjmp.h>        /* jmp_buf */
#define INCLUDED_setjmp_h
#endif

#include "main.h"          /* struct aldWorkspace */
struct aldWorkspace;

struct Command
{
  char *cmd;          /* command name */
  int (* funcptr)();  /* function to call */
  unsigned int flags; /* C_xxx bitmasks */
};

struct commandWorkspace
{
  char *CmdPrompt;            /* command prompt string */
  jmp_buf CmdParserEnv;       /* environment for procCommand() */
};

/*
 * Various command bitmasks
 */
#define C_ALIAS              (1 << 0) /* command is an alias for another */
#define C_PROCESS            (1 << 1) /* command requires a debugee process */
#define C_FILELOADED         (1 << 2) /* needs a file loaded (via "load") */
#define C_AMBIGUOUS          (1 << 3) /* command is ambiguous */
#define C_PTRACE             (1 << 4) /* command uses ptrace call */
#define C_PROCESS_RUNNING    (1 << 5) /* command requires running process */

/*
 * Prototypes
 */

struct commandWorkspace *initCommand();
void termCommand(struct commandWorkspace *ws);
int procCommand(struct aldWorkspace *main_p);

struct Command *FindCommand(struct Command *cmdlist, char *name,
                            unsigned int *flags);

int c_attach(struct aldWorkspace *ws, int ac, char **av);
int c_break(struct aldWorkspace *ws, int ac, char **av);
int c_continue(struct aldWorkspace *ws, int ac, char **av);
int c_dbreak(struct aldWorkspace *ws, int ac, char **av);
int c_detach(struct aldWorkspace *ws, int ac, char **av);
int c_disable(struct aldWorkspace *ws, int ac, char **av);
int c_disassemble(struct aldWorkspace *ws, int ac, char **av);
int c_display(struct aldWorkspace *ws, int ac, char **av);
int c_enable(struct aldWorkspace *ws, int ac, char **av);
int c_enter(struct aldWorkspace *ws, int ac, char **av);
int c_examine(struct aldWorkspace *ws, int ac, char **av);
int c_file(struct aldWorkspace *ws, int ac, char **av);
int c_help(struct aldWorkspace *ws, int ac, char **av);
int c_ignore(struct aldWorkspace *ws, int ac, char **av);
int c_lbreak(struct aldWorkspace *ws, int ac, char **av);
int c_ldisplay(struct aldWorkspace *ws, int ac, char **av);
int c_load(struct aldWorkspace *ws, int ac, char **av);
int c_next(struct aldWorkspace *ws, int ac, char **av);
int c_quit(struct aldWorkspace *ws, int ac, char **av);
int c_register(struct aldWorkspace *ws, int ac, char **av);
int c_run(struct aldWorkspace *ws, int ac, char **av);
int c_set(struct aldWorkspace *ws, int ac, char **av);
int c_step(struct aldWorkspace *ws, int ac, char **av);
int c_tbreak(struct aldWorkspace *ws, int ac, char **av);
int c_undisplay(struct aldWorkspace *ws, int ac, char **av);
int c_unload(struct aldWorkspace *ws, int ac, char **av);

/*
 * External declarations
 */

extern jmp_buf *CmdParserEnvPtr;

#endif /* INCLUDED_command_h */
