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
 * $Id: traceresult.c,v 1.1.1.1 2004/04/26 00:40:41 pa33 Exp $
 */

#include <errno.h>
#include <string.h>

#include "main.h"
#include "misc.h"
#include "msg.h"
#include "print.h"
#include "signals.h"

/*
analyzeTraceResult()
  This function is called after the commands {step, next, run,
continue} have been executed. Each of these commands call a ptrace
routine to perform a task, and these ptrace routines all return the
same value depending upon what happens. So instead of duplicating
switch statement for all of those commands, this is a common routine
to analyze the return result and take appropriate action.

Inputs: ws     - main workspace
        result - return result from the ptrace routine
        data   - possibly modified data

Return: 1 if everything is normal
        0 if an error occurred, or if the program terminated (due to
        a signal or normally)

Note: if an error occurs, a message will be displayed
*/

int
analyzeTraceResult(struct aldWorkspace *ws, int result, int data)

{
  int ret;

  ret = 1;

  switch (result)
  {
    /*
     * ptrace() failed
     */
    case 0:
    {
      Print(ws, P_ERROR, MSG_PTERR, strerror(errno));
      ret = 0;

      break;
    }

    case 1:
    {
      /*
       * Everything went well
       */
      break;
    }

    /*
     * program stopped due to a signal
     */
    case 2:
    {
      struct aSignal *sptr;

      sptr = GetSignal(data);
      if (sptr)
      {
        Print(ws,
              P_COMMAND,
              MSG_GOTSIGNAL,
              sptr->name,
              sptr->desc,
              getAddressDebug(ws->debugWorkspace_p));
      }
      else
      {
        /*
         * The program received an unknown signal
         */
        Print(ws,
              P_COMMAND,
              MSG_GOTUNKNOWNSIG,
              data,
              getAddressDebug(ws->debugWorkspace_p));
      }

      break;
    }

    /*
     * Breakpoint encountered
     */
    case 3:
    {
      Print(ws,
            P_COMMAND,
            MSG_BKPTENCOUNTERED,
            data,
            getAddressDebug(ws->debugWorkspace_p));

      break;
    }

    /*
     * program terminated normally
     */
    case 4:
    {
      Print(ws, P_COMMAND, MSG_PROGDONE, data);

      endProcess(ws);

      ret = 0;

      break;
    }

    /*
     * program output some data
     */
    case 5:
    {
    }

    /*
     * program is not executable
     */
    case 6:
    {
      Print(ws, P_COMMAND, MSG_PROGNOEXEC, ws->objectFileName);

      ret = 0;

      break;
    }

    /*
     * program terminated due to a signal
     */
    case 7:
    {
      struct aSignal *sptr;

      sptr = GetSignal(data);
      if (sptr)
      {
        Print(ws,
              P_COMMAND,
              MSG_PROGTERMSIG,
              sptr->name,
              sptr->desc);
      }
      else
      {
        Print(ws,
              P_COMMAND,
              MSG_PROGTERMUNKNOWNSIG,
              data);
      }

      endProcess(ws);

      ret = 0;

      break;
    }

    default: break;
  } /* switch (result) */

  return (ret);
} /* analyzeTraceResult() */
