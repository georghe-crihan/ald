/*
 * libDebug
 *
 * Copyright (C) 2000 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: args.c,v 1.1.1.1 2004/04/26 00:41:09 pa33 Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "libDebug.h"

/*
SplitArgs()
  Break up strings separated by a space and store them
into an array of pointers

Inputs: buffer - string composed of substrings separated by 'delim'
        array  - array of pointers to construct with substrings

Return: number of substrings in 'buffer'
*/

int
SplitArgs(char *buffer, char ***array)

{
  int argsize = 1;
  int acnt;
  char *temp, *bufptr;

  bufptr = buffer;

  /*
   * Make sure there are no preceding spaces
   */
  while (isspace((unsigned char) *bufptr))
    ++bufptr;

  /*
   * Kill the ending \n (if there is one)
   */
  if ((temp = strchr(bufptr, '\n')))
    *temp = '\0';

  *array = (char **) malloc(sizeof(char *) * argsize);
  acnt = 0;

  while (*bufptr)
  {
    if (acnt == argsize)
    {
      ++argsize;
      *array = (char **) realloc(*array, sizeof(char *) * argsize);
    }

    temp = strchr(bufptr, ' ');
    if (temp)
    {
      *temp++ = '\0';
      while (isspace((unsigned char) *temp))
        ++temp;
    }
    else
      temp = bufptr + strlen(bufptr);

    (*array)[acnt++] = bufptr;
    bufptr = temp;
  }

  /*
   * We must terminate the array with a NULL for the execv() call
   */
  ++argsize;
  *array = (char **) realloc(*array, sizeof(char *) * argsize);
  (*array)[acnt] = 0;

  return (acnt);
} /* SplitArgs() */
