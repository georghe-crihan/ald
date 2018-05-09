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
 * $Id: c_register.c,v 1.1.1.1 2004/04/26 00:40:45 pa33 Exp $
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "alddefs.h"
#include "main.h"
#include "msg.h"
#include "output.h"
#include "print.h"
#include "registers.h"

#include "libDebug.h"

/*
 * libString includes
 */
#include "Strn.h"

/*
c_register()
  Display/manipulate registers

Usage: register [name [value]]

Return: 0 upon failure
        1 upon success
*/

int
c_register(struct aldWorkspace *ws, int ac, char **av)

{
  int rindex;
  char regval[MAXLINE + 1];
  int sret;     /* return value from setRegisterDebug() */

  if (ac < 2)
  {
    /*
     * No arguments - they want a list of general registers
     */
    displayRegisters(ws, NOREG, 1, DB_REGFL_DISPLAY_GENERAL);
    return (1);
  }

  if (!Strncasecmp(av[1], "-all", strlen(av[1])))
  {
    /*
     * Display all registers
     */
    displayRegisters(ws, NOREG, 0, DB_REGFL_DISPLAY_ALL);
    return (1);
  }

  /*
   * They want the value of a specific register (ac > 1)
   */
  rindex = findRegisterDebug(ws->debugWorkspace_p, av[1]);
  if (rindex == (-1))
  {
    /*
     * Register was not found
     */
    Print(ws, P_COMMAND, "Invalid register: %s", av[1]);
    return (0);
  }

  if (ac > 2)
  {
    /*
     * Check if they gave a value to set the register to
     */

    strncpy(regval, av[2], MAXLINE);

    sret = setRegisterDebug(ws->debugWorkspace_p, rindex, regval);

    if (sret == (-2))
    {
      /*
       * invalid value
       */
      Print(ws, P_ERROR, "Invalid register value: %s", regval);
      return (0);
    }
    else if (sret == (-1))
    {
      /*
       * ptrace error
       */
      Print(ws, P_ERROR, MSG_PTERR, strerror(errno));
      return (0);
    }
  }
  else
  {
    /*
     * Output the value of the register they are interested
     * in
     */
    displayRegisters(ws, rindex, 0, 0);
  } /* if (ac <= 2) */

  return (1);
} /* c_register() */
