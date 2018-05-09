/*
 * libString
 *
 * Copyright (C) 1998-1999 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: SplitBuffer.c,v 1.1.1.1 2004/04/26 00:40:54 pa33 Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "alloc.h"
#include "Strn.h"

/*
 * Number of slots in our array to allocate at once
 */
#define BUF_ARGSIZE  4

/*
SplitBuffer()
 Take string "buffer" and insert NULLs in the spaces between words.
Keep pointers to the beginning of each word, and store them
in "array".
 Returns the number of words in "buffer"
*/

int
SplitBuffer(char *buffer, char ***array)

{
  return (SplitBufferDelim(buffer, array, (unsigned char) ' '));
} /* SplitBuffer() */

/*
SplitBufferDelim()
  Break up strings separated by a given delimiter and store them
into an array of pointers. Characters between quotes are treated
as one string, no matter what delimiters are in between.

Inputs: buffer - string composed of substrings separated by 'delim'
        array  - array of pointers to construct with substrings
        delim  - separating character between substrings

Return: number of substrings in 'buffer' if successful
        -1 if unbalanced quotes - in this case, no memory is
        allocated so the calling function need not free anything
*/

int
SplitBufferDelim(char *buffer, char ***array, unsigned char delim)

{
  int argsize = BUF_ARGSIZE;
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
      argsize += BUF_ARGSIZE;
      *array = (char **) realloc(*array, sizeof(char *) * argsize);
    }

    if (*bufptr == '"')
    {
      /*
       * Attempt to find ending quote
       */
      temp = strchr(bufptr + 1, (unsigned char) '"');
      if (!temp)
      {
        /*
         * Unbalanced quotes
         */
        MyFree(*array);
        return (-1);
      }

      *temp++ = '\0';
      while ((unsigned char) *temp == delim)
        ++temp;

      (*array)[acnt++] = bufptr + 1;
      bufptr = temp;

      continue;
    } /* if (*bufptr == '"') */

    temp = strchr(bufptr, delim);
    if (temp)
    {
      *temp++ = '\0';
      while ((unsigned char) *temp == delim)
        ++temp;
    }
    else
      temp = bufptr + strlen(bufptr);

    (*array)[acnt++] = bufptr;
    bufptr = temp;
  }

  return (acnt);
} /* SplitBufferDelim() */
