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
 * $Id: signals.c,v 1.1.1.1 2004/04/26 00:40:51 pa33 Exp $
 */

#include <stdio.h>
#include <signal.h>
#include <setjmp.h>

#include "command.h"
#include "signals.h"

struct aSignal Signals[] = {
  { "0",          "Signal 0" },                          /**/
  { "SIGHUP",     "Hangup" },                            /* 1 */
  { "SIGINT",     "Interrupt" },                         /* 2 */
  { "SIGQUIT",    "Quit" },                              /* 3 */
  { "SIGILL",     "Illegal instruction" },               /* 4 */
  { "SIGTRAP",    "Trace/Breakpoint trap" },             /* 5 */
  { "SIGABRT",    "Aborted" },                           /* 6 */
  { "SIGEMT",     "Emulation trap" },                    /* 7 */
  { "SIGFPE",     "Arithmetic exception" },              /* 8 */
  { "SIGKILL",    "Killed" },                            /* 9 */
  { "SIGBUS",     "Bus error" },                         /* 10 */
  { "SIGSEGV",    "Segmentation fault" },                /* 11 */
  { "SIGSYS",     "Nonexistant system call" },           /* 12 */
  { "SIGPIPE",    "Broken pipe" },                       /* 13 */
  { "SIGALRM",    "Alarm" },                             /* 14 */
  { "SIGTERM",    "Terminated" },                        /* 15 */
  { "SIGURG",     "Urgent condition on I/O channel" },   /* 16 */
  { "SIGSTOP",    "Stopped (not from tty)" },            /* 17 */
  { "SIGTSTP",    "Stopped (from tty)" },                /* 18 */
  { "SIGCONT",    "Continue process" },                  /* 19 */
  { "SIGCHLD",    "Child status changed" },              /* 20 */
  { "SIGTTIN",    "Stopped (tty input)" },               /* 21 */
  { "SIGTTOU",    "Stopped (tty output)" },              /* 22 */
  { "SIGIO",      "I/O possible" },                      /* 23 */
  { "SIGXCPU",    "CPU time limit exceeded" },           /* 24 */
  { "SIGXFSZ",    "File size limit exceeded" },          /* 25 */
  { "SIGVTALRM",  "Virtual timer expired" },             /* 26 */
  { "SIGPROF",    "Profiling timer expired" },           /* 27 */
  { "SIGWINCH",   "Window size changed" },               /* 28 */
  { "SIGLOST",    "Resource lost" },                     /* 29 */
  { "SIGUSR1",    "User defined signal 1" },             /* 30 */
  { "SIGUSR2",    "User defined signal 2" },             /* 31 */
};

/*
GetSignal()
  Find a signal description

Inputs: signum - signal number

Return: pointer to index of Signals[] corresponding to given signal
*/

struct aSignal *
GetSignal(int signum)

{
#if defined(SIGHUP)
  if (signum == SIGHUP)
    return (&Signals[MYSIG_HUP]);
#endif

#if defined(SIGINT)
  else if (signum == SIGINT)
    return (&Signals[MYSIG_INT]);
#endif

#if defined(SIGQUIT)
  else if (signum == SIGQUIT)
    return (&Signals[MYSIG_QUIT]);
#endif

#if defined(SIGILL)
  else if (signum == SIGILL)
    return (&Signals[MYSIG_ILL]);
#endif

#if defined(SIGTRAP)
  else if (signum == SIGTRAP)
    return (&Signals[MYSIG_TRAP]);
#endif

#if defined(SIGABRT)
  else if (signum == SIGABRT)
    return (&Signals[MYSIG_ABRT]);
#endif

#if defined(SIGEMT)
  else if (signum == SIGEMT)
    return (&Signals[MYSIG_EMT]);
#endif

#if defined(SIGFPE)
  else if (signum == SIGFPE)
    return (&Signals[MYSIG_FPE]);
#endif

#if defined(SIGKILL)
  else if (signum == SIGKILL)
    return (&Signals[MYSIG_KILL]);
#endif

#if defined(SIGBUS)
  else if (signum == SIGBUS)
    return (&Signals[MYSIG_BUS]);
#endif

#if defined(SIGSEGV)
  else if (signum == SIGSEGV)
    return (&Signals[MYSIG_SEGV]);
#endif

#if defined(SIGSYS)
  else if (signum == SIGSYS)
    return (&Signals[MYSIG_SYS]);
#endif

#if defined(SIGPIPE)
  else if (signum == SIGPIPE)
    return (&Signals[MYSIG_PIPE]);
#endif

#if defined(SIGALRM)
  else if (signum == SIGALRM)
    return (&Signals[MYSIG_ALRM]);
#endif

#if defined(SIGTERM)
  else if (signum == SIGTERM)
    return (&Signals[MYSIG_TERM]);
#endif

#if defined(SIGURG)
  else if (signum == SIGURG)
    return (&Signals[MYSIG_URG]);
#endif

#if defined(SIGSTOP)
  else if (signum == SIGSTOP)
    return (&Signals[MYSIG_STOP]);
#endif

#if defined(SIGTSTP)
  else if (signum == SIGTSTP)
    return (&Signals[MYSIG_TSTP]);
#endif

#if defined(SIGCONT)
  else if (signum == SIGCONT)
    return (&Signals[MYSIG_CONT]);
#endif

#if defined(SIGCHLD)
  else if (signum == SIGCHLD)
    return (&Signals[MYSIG_CHLD]);
#endif

#if defined(SIGTTIN)
  else if (signum == SIGTTIN)
    return (&Signals[MYSIG_TTIN]);
#endif

#if defined(SIGTTOU)
  else if (signum == SIGTTOU)
    return (&Signals[MYSIG_TTOU]);
#endif

#if defined(SIGIO)
  else if (signum == SIGIO)
    return (&Signals[MYSIG_IO]);
#endif

#if defined(SIGXCPU)
  else if (signum == SIGXCPU)
    return (&Signals[MYSIG_XCPU]);
#endif

#if defined(SIGXFSZ)
  else if (signum == SIGXFSZ)
    return (&Signals[MYSIG_XFSZ]);
#endif

#if defined(SIGVTALRM)
  else if (signum == SIGVTALRM)
    return (&Signals[MYSIG_VTALRM]);
#endif

#if defined(SIGPROF)
  else if (signum == SIGPROF)
    return (&Signals[MYSIG_PROF]);
#endif

#if defined(SIGWINCH)
  else if (signum == SIGWINCH)
    return (&Signals[MYSIG_WINCH]);
#endif

#if defined(SIGLOST)
  else if (signum == SIGLOST)
    return (&Signals[MYSIG_LOST]);
#endif

#if defined(SIGUSR1)
  else if (signum == SIGUSR1)
    return (&Signals[MYSIG_USR1]);
#endif

#if defined(SIGUSR2)
  else if (signum == SIGUSR2)
    return (&Signals[MYSIG_USR2]);
#endif

#if defined(SIGPWR)
  else if (signum == SIGPWR)
    return (&Signals[MYSIG_PWR]);
#endif

#if defined(SIGPOLL)
  else if (signum == SIGPOLL)
    return (&Signals[MYSIG_POLL]);
#endif

  /*
   * Unknown signal - shouldn't happen
   */
  return (0);
} /* GetSignal() */

/*
SetupSignals()
  Setup various signal handlers for the debugger on startup

Return: none
*/

void
SetupSignals()

{
  /*
   * For now, ignore SIGINT. Later, when the interactive command
   * parser sets up the setjmp/longjmp stuff, it will redirect
   * SIGINT to our handler so our handler will know that if
   * a SIGINT is generated, it is ok to longjmp().
   */
  signal(SIGINT, SIG_IGN);
} /* SetupSignals() */

/*
SigHandler()
  Handle various signals when they are generated
*/

void
SigHandler(int sig)

{
  switch (sig)
  {
    case SIGINT:
    {
      /*
       * When the user hits ^C we want halt the current command and
       * return to GetCommandInput() to get the next one etc. If
       * this handler is called with SIGINT, we can safely assume
       * that GetCommandInput() has already called setjmp(CmdParserEnv)
       * and so we can safely longjmp() to it.
       */
      longjmp(*CmdParserEnvPtr, SIGINT);
      break; /* not reached */
    }

    default: break;
  } /* switch (sig) */
} /* SigHandler() */
