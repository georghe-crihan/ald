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
 * $Id: command.c,v 1.4 2004/10/10 05:29:50 pa33 Exp $
 */

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>

#include "alddefs.h"
#include "command.h"
#include "defs.h"
#include "input.h"
#include "list.h"
#include "load.h"
#include "main.h"
#include "misc.h"
#include "msg.h"
#include "print.h"
#include "readln.h"
#include "signals.h"
#include "terminal.h"

/*
 * libString includes
 */
#include "alloc.h"
#include "Strn.h"

static int ProcessCommand(struct aldWorkspace *main_p, char *command);

/*
 * Global: pointer to command parser environment. This needs to
 * be global because SigHandler() needs it.
 */
jmp_buf            *CmdParserEnvPtr = 0;

static struct Command mainCmds[] = {
  /*
   * Aliases - put these at the top since they are used
   * frequently
   */
  { "c", c_continue, C_ALIAS|C_PROCESS|C_PTRACE },
  { "d", c_disassemble, C_ALIAS|C_FILELOADED },
  { "e", c_examine, C_ALIAS|C_PROCESS },
  { "n", c_next, C_ALIAS|C_PROCESS|C_PTRACE },
  { "r", c_run, C_ALIAS|C_PROCESS|C_PTRACE },
  { "s", c_step, C_ALIAS|C_PROCESS|C_PTRACE },

  { "attach", c_attach, C_PTRACE },
  { "break", c_break, C_PROCESS },
  { "continue", c_continue, C_PROCESS|C_PTRACE },
  { "dbreak", c_dbreak, 0 },
  { "delete", c_dbreak, C_ALIAS },
  { "detach", c_detach, C_PTRACE },
  { "disable", c_disable, 0 },
  { "disassemble", c_disassemble, C_FILELOADED },
  { "display", c_display, C_PROCESS },
  { "dump", c_examine, C_ALIAS|C_PROCESS },
  { "enable", c_enable, 0 },
  { "enter", c_enter, C_PROCESS },
  { "examine", c_examine, C_PROCESS },
  { "exit", c_quit, C_ALIAS },
  { "file", c_file, C_FILELOADED },
  { "help", c_help, 0 },
  { "ignore", c_ignore, 0 },
  { "lbreak", c_lbreak, 0 },
  { "ldisplay", c_ldisplay, C_PROCESS },
  { "load", c_load, 0 },
  { "next", c_next, C_PROCESS|C_PTRACE },
  { "quit", c_quit, 0 },
  { "register", c_register, C_PROCESS_RUNNING },
  { "run", c_run, C_PROCESS|C_PTRACE },
  { "set", c_set, 0 },
  { "step", c_step, C_PROCESS|C_PTRACE },
  { "store", c_enter, C_ALIAS|C_PROCESS },
  { "tbreak", c_tbreak, C_PROCESS },
  { "undisplay", c_undisplay, C_PROCESS },
  { "unload", c_unload, C_FILELOADED },

  { 0, 0, 0 }
};

/*
initCommand()
  Initialize a command workspace

Return: pointer to workspace
*/

struct commandWorkspace *
initCommand()

{
  struct commandWorkspace *ws;

  ws = (struct commandWorkspace *) malloc(sizeof(struct commandWorkspace));
  if (!ws)
  {
    fprintf(stderr, "initCommand: malloc failed: %s\n",
      strerror(errno));
    return (0);
  }

  memset(ws, '\0', sizeof(struct commandWorkspace));

  ws->CmdPrompt = Strdup(ALD_PROMPT);

  return (ws);
} /* initCommand() */

/*
termCommand()
  Terminate a command workspace

Inputs: ws - workspace to terminate
*/

void
termCommand(struct commandWorkspace *ws)

{
  if (!ws)
    return;

  if (ws->CmdPrompt)
    free(ws->CmdPrompt);

  free(ws);
} /* termCommand() */

/*
procCommand()
  Enter infinite loop to wait for and process user commands

Inputs: ws - main workspace

Return: 0 upon failure, otherwise will never return
*/

int
procCommand(struct aldWorkspace *ws)

{
  struct commandWorkspace *command_p = ws->commandWorkspace_p;
  char buffer[MAXLINE + 1];
  char last[MAXLINE + 1]; /* last command entered */
  char *bufptr,
       *cmdptr;
  int GotLongJmp;         /* did we get called from longjmp()? */
  int ret;
  struct genericList *lptr;

  *last = '\0';
  ret = 1;

  while (ret >= 0)
  {
    GotLongJmp = setjmp(command_p->CmdParserEnv);
    if (GotLongJmp)
    {
      /*
       * In case we were in the middle of a print burst and the
       * user ^C'd, clear the burst flag
       */
      endPrintBurst(ws->printWorkspace_p);

      restoreTerminal(&(ws->terminalWorkspace_p->ParentAttributes));
      printf("\n");

      /*
       * If there was any temporary memory allocated before the
       * print burst, free it now
       */
      freeList(&(ws->toBeFreed));
    }

    /*
     * Read a line from stdin
     */
    bufptr = ReadLine(ws);
    assert(bufptr != 0);

    if ((*bufptr == '\0') || (*bufptr == '\n'))
    {
      /*
       * Use the last command entered - put 'last' back into
       * 'buffer' so it doesn't get destroyed by ProcessCommand()
       */
      strncpy(buffer, last, MAXLINE);
      cmdptr = buffer;
    }
    else
    {
      /*
       * Save this command for later use
       */
      strncpy(last, bufptr, MAXLINE);
      last[MAXLINE] = '\0';
      cmdptr = bufptr;
    }

    lptr = insertList(&(ws->toBeFreed), (void *) bufptr);

    /*
     * Process given command
     */
    ret = ProcessCommand(ws, cmdptr);

    FreeLine(bufptr);

    deleteList(&(ws->toBeFreed), lptr);
  } /* while (ret >= 0) */

  /*
   * If we get here, a fatal error occured, or the user
   * quit the program.
   */
  return (0);
} /* procCommand() */

/*
ProcessCommand()
  Process a given command

Inputs: ws      - main workspace
        command - command

Return: 1 upon success
        0 upon error
        -1 upon fatal error
*/

static int
ProcessCommand(struct aldWorkspace *ws, char *command)

{
  int ac;
  char **av;
  struct Command *cptr;
  unsigned int flags;
  int ret;
  struct genericList *lptr;

  assert(command != 0);

  ac = SplitBuffer(command, &av);

  if (!ac)
    return (0);

  if (ac == (-1))
  {
    Print(ws, P_ERROR, "Unbalanced quotes");
    return (0);
  }

  flags = 0;
  cptr = FindCommand(mainCmds, av[0], &flags);

  if (!cptr)
  {
    if (flags & C_AMBIGUOUS)
    {
      Print(ws, P_ERROR, "Ambiguous command: %s", av[0]);
    }
    else
    {
      Print(ws,
            P_ERROR,
            "Unknown command: %s (help shows a list)",
            av[0]);
    }

    free(av);
    return (0);
  }

  if ((cptr->flags & C_FILELOADED) && !awIsFileLoaded(ws))
  {
    Print(ws, P_ERROR, MSG_NOFILELOADED);
    free(av);
    return (0);
  }

  if ((cptr->flags & C_PROCESS) && !awIsAttached(ws) &&
      !awIsFileLoaded(ws))
  {
    /*
     * This command requires a ptraced process, but there are none
     * currently
     */
    Print(ws, P_ERROR, MSG_NOPROCESS);
    free(av);
    return (0);
  }

  if ((cptr->flags & C_PROCESS_RUNNING) &&
      !isRunningDebug(ws->debugWorkspace_p))
  {
    /*
     * This command requires the process to be running, but it
     * has not been executed yet
     */
    Print(ws, P_ERROR, MSG_NOPROCESS);
    free(av);
    return (0);
  }

  if (cptr->flags & C_PTRACE)
  {
    /*
     * The command we are about to execute will be using the ptrace()
     * system call - do not catch SIGINT, in case the console user
     * hits ^C while the ptraced process is running - we don't
     * want to longjmp() back to procCommand() in the middle
     * of the ptrace()
     */
    signal(SIGINT, SIG_IGN);
  }
  else
  {
    /*
     * Hook SIGINT to our signal handler, in case we are about
     * to execute a command which bursts a lot of info - the user
     * will have the ability to hit CONTROL-C and stop the execution
     * of the command.
     * This must be set up after the setjmp() call in procCommand()
     * or things will be very bad if ^C is pressed beforehand
     * (ie: the SigHandler longjmp() call will jump to who knows where)
     */
    signal(SIGINT, SigHandler);
  }

  /*
   * The command we execute may do print bursts, and the user
   * may stop the burst before it completes, meaning the following
   * free(av) won't be executed. So add 'av' to our list of to
   * be freed items to make sure it is freed in case we do a
   * longjmp().
   */
  lptr = insertList(&(ws->toBeFreed), (void *) av);

  /*
   * Execute the command
   */
  ret = (*cptr->funcptr)(ws, ac, av);

  free(av);

  /*
   * If we get here, no longjmp() was issued, so 'av' was
   * freed normally. Remove it from the to be freed list.
   */
  deleteList(&(ws->toBeFreed), lptr);

  if (ret < 0)
    return (ret);

  return (1);
} /* ProcessCommand() */

/*
FindCommand()
 Attempt to find the command "name" in the array "cmdlist"

Inputs: cmdlist - array to look in
        name    - command name
        flags   - bitmasks

Return: pointer to the index containing "name" if found,
        otherwise NULL.
        If the command is found, but there is more than 1 match
        (ambiguous), set the C_AMBIGUOUS bit in 'flags'
*/

struct Command *
FindCommand(struct Command *cmdlist, char *name, unsigned int *flags)

{
  struct Command *cmdptr, *tmp;
  int matches; /* number of matches we've had so far */
  size_t clength;

  assert(name != 0);
  assert(cmdlist != 0);

  tmp = NULL;
  matches = 0;
  clength = strlen(name);
  for (cmdptr = cmdlist; cmdptr->cmd; ++cmdptr)
  {
    if (!Strncasecmp(name, cmdptr->cmd, clength))
    {
      if (clength == strlen(cmdptr->cmd))
      {
        /*
         * name and cmdptr->cmd are the same length, so it
         * must be an exact match, don't search any further
         */
        matches = 0;
        break;
      }
      tmp = cmdptr;
      ++matches;
    }
  }

  /*
   * If matches > 1, name is an ambiguous command, so the
   * user needs to be more specific
   */
  if ((matches == 1) && (tmp))
    cmdptr = tmp;

  if (cmdptr->cmd)
    return (cmdptr);

  if (matches != 0)
    *flags |= C_AMBIGUOUS;

  return (0);
} /* FindCommand() */
