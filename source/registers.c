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
 * $Id: registers.c,v 1.2 2004/10/09 17:47:15 pa33 Exp $
 */

#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "alddefs.h"
#include "defs.h"
#include "main.h"
#include "msg.h"
#include "print.h"
#include "registers.h"

#include "libDebug.h"

/*
 * libString includes
 */
#include "alloc.h"

static void displayRegsNormalCallback(struct debugRegisterInfo *regInfo, void *args);
static void displayRegsCompactCallback(struct debugRegisterInfo *regInfo, void *args);

/*
displayRegisters()
  Display one or more registers and their contents

Inputs: ws       - main workspace
        regindex - optional index of specific register to display
        compact  - display registers in compact form

Return: none
*/

void
displayRegisters(struct aldWorkspace *ws, int regindex, int compact, unsigned int flgs)

{
  struct callbackArgs displayArgs;
  char flags[MAXLINE];
  int ret;

  displayArgs.main_p = ws;
  displayArgs.regcount = 0;

  if (compact)
  {
    ret = printRegistersDebug(ws->debugWorkspace_p,
                              regindex,
                              flgs,
                              displayRegsCompactCallback,
                              (void *) &displayArgs);

    if (ret == 0)
    {
      /*
       * ptrace error
       */
      Print(ws, P_ERROR, MSG_PTERR, strerror(errno));
      return;
    }

    if (displayArgs.regcount != 0)
      RawPrint(ws, P_REGISTER, "\n");
  }
  else
  {
    startPrintBurst(ws->printWorkspace_p);

    ret = printRegistersDebug(ws->debugWorkspace_p,
                              regindex,
                              flgs,
                              displayRegsNormalCallback,
                              (void *) &displayArgs);

    if (ret == 0)
    {
      /*
       * ptrace error
       */
      Print(ws, P_ERROR, MSG_PTERR, strerror(errno));
      return;
    }

    endPrintBurst(ws->printWorkspace_p);
  }

  if ((regindex == NOREG) && (flgs & DB_REGFL_DISPLAY_GENERAL))
  {
    /*
     * Print out flags register in readable format
     */
    ret = getFlagsDebug(ws->debugWorkspace_p, flags);
    if (ret)
      Print(ws, P_COMMAND, "\nFlags: %s\n", flags);
  }
} /* displayRegisters() */

/*
displayRegsNormalCallback()
  This function is called from getRegistersCallbackDebug() with the name and
contents of a specific register - output the information to the console

Inputs: regInfo - register information
        args    - callback arguments

Return: none
*/

static void
displayRegsNormalCallback(struct debugRegisterInfo *regInfo, void *args)

{
  struct callbackArgs *cargs = (struct callbackArgs *) args;
  long double *dval;

  if (regInfo->flags & DB_RI_BREAK)
  {
    /*
     * This indicates a break between different register types
     * ie: general/fpu/mmx etc
     */
    return;
  }
  else if (regInfo->flags & DB_RI_FPU_DATA)
  {
    dval = (long double *) regInfo->rawbuf;
    sprintf(cargs->scratch, "%.17g", (double) (*dval));

    Print(cargs->main_p,
          P_REGISTER,
          "%-10s %-30s (%s)",
          regInfo->name,
          cargs->scratch,
          regInfo->hexvalue);
  }
  else if (regInfo->flags & DB_RI_FPU_SEGOFF)
  {
    sprintf(cargs->scratch, "0x%02X:0x%08lX", regInfo->seg, regInfo->off);

    Print(cargs->main_p,
          P_REGISTER,
          "%-10s %-30s",
          regInfo->name,
          cargs->scratch);
  }
  else if (regInfo->flags & DB_RI_MMX)
  {
    Print(cargs->main_p,
          P_REGISTER,
          "%-10s %s",
          regInfo->name,
          regInfo->hexvalue);
  }
  else
  {
    sprintf(cargs->scratch,
            "0x%0*lX",
            regInfo->size << 1,
            regInfo->value);

    Print(cargs->main_p,
          P_REGISTER,
          "%-10s %-30s (%lu)",
          regInfo->name,
          cargs->scratch,
          regInfo->value);
  }
} /* displayRegsNormalCallback() */

/*
displayRegsCompactCallback()
  This function is called from getRegistersCallbackDebug() with the name and
contents of a specific register - output the information to the console in
compact form

Inputs: regInfo - register information
        args    - callback arguments

Return: none
*/

static void
displayRegsCompactCallback(struct debugRegisterInfo *regInfo, void *args)

{
  struct callbackArgs *cargs = (struct callbackArgs *) args;
  long double *dval;

  if (regInfo->flags & DB_RI_BREAK)
  {
    /*
     * This indicates a break between different register types
     * ie: general/fpu/mmx etc
     */
    RawPrint(cargs->main_p, P_REGISTER, "\n");
    cargs->regcount = 0;

    return;
  }
  else if (regInfo->flags & DB_RI_FPU_DATA)
  {
    dval = (long double *) regInfo->rawbuf;
    sprintf(cargs->scratch, "%.9g", (double) (*dval));

    RawPrint(cargs->main_p,
             P_REGISTER,
             "%-3s = %s ",
             regInfo->name,
             cargs->scratch);
  }
  else if (regInfo->flags & DB_RI_FPU_SEGOFF)
  {
    sprintf(cargs->scratch, "0x%02X:0x%08lX", regInfo->seg, regInfo->off);

    RawPrint(cargs->main_p,
             P_REGISTER,
             "%-3s = %s ",
             regInfo->name,
             cargs->scratch);
  }
  else if (regInfo->flags & DB_RI_MMX)
  {
    RawPrint(cargs->main_p,
             P_REGISTER,
             "%-3s = %s ",
             regInfo->name,
             regInfo->hexvalue);
    ++(cargs->regcount);
  }
  else
  {
    RawPrint(cargs->main_p,
             P_REGISTER,
             "%-3s = 0x%0*lX ",
             regInfo->name,
             regInfo->size << 1,
             regInfo->value);
  }

  if (++(cargs->regcount) >= 4)
  {
    RawPrint(cargs->main_p, P_REGISTER, "\n");
    cargs->regcount = 0;
  }
} /* displayRegsCompactCallback() */
