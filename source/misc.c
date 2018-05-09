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
 * $Id: misc.c,v 1.1.1.1 2004/04/26 00:40:49 pa33 Exp $
 */

#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>

#include "alddefs.h"
#include "config.h"
#include "defs.h"
#include "load.h"
#include "main.h"

/*
endProcess()
  Called when our debugged process terminates (normally or due to a signal etc) -
do some cleanup

Inputs: ws - main workspace
*/

void
endProcess(struct aldWorkspace *ws)

{
  awClearAttached(ws);
} /* endProcess() */

/*
debug()
 Log given string to file DEBUGLOG
*/

void
debug(char *format, ...)

{
#ifdef DEBUGMODE

  FILE *fp;
  va_list args;

  if (!(fp = fopen(DEBUGLOG, "a+")))
    return;

  va_start(args, format);

  vfprintf(fp, format, args);

  va_end(args);

  fclose(fp);

#endif /* DEBUGMODE */
} /* debug() */

/*
StrToBool()
  Determine if the given string represents a boolean true or false.

Return: 1 if string is "yes", "on", or "true"
        0 if string is "no", "off", or "false"
        -1 if string is not a boolean value
*/

int
StrToBool(const char *str)

{
  register char c;

  c = tolower(*str);
  switch (c)
  {
    case 'y':  /* yes */
    case 't':  /* true */
    {
      return (1);
      break; /* not reached */
    }

    case 'n':  /* no */
    case 'f':  /* false */
    {
      return (0);
      break; /* not reached */
    }

    case 'o':  /* test for "on" or "off" */
    {
      c = tolower(*++str);
      if (c == 'f')
        return (0);
      else
        return (1);

      break; /* not reached */
    }

    default:  /* 1 (= true), 0 or another number (= false) */
    {
      long num;
      char *endptr;

      num = strtol(str, &endptr, 10);
      if ((endptr == str) || (*endptr != '\0'))
        return (-1); /* invalid number string */

      if (num == 0)
        return (0);
      else
        return (1);

      break; /* not reached */
    }
  } /* switch (c) */

  /* not reached */
  return (-1);
} /* StrToBool() */
