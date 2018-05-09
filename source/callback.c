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
 * $Id: callback.c,v 1.1.1.1 2004/04/26 00:40:41 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "alddefs.h"
#include "print.h"

#include "Strn.h"

/*
callbackPrintOFF()
  Callback function passed to libOFF when printing information
about file format (headers, symbols, sections, etc).
*/

void
callbackPrintOFF(void *args, const char *format, ...)

{
  va_list ap;

  va_start(ap, format);

  PrintWindow((struct aldWorkspace *) args,
              0,
              format,
              ap);

  va_end(ap);
} /* callbackPrintOFF() */
