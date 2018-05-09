/*
 * libString
 *
 * Copyright (C) 1999-2000 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: Strdup.c,v 1.1.1.1 2004/04/26 00:40:54 pa33 Exp $
 */

#include <string.h>
#include <assert.h>

#include "alloc.h"
#include "Strn.h"

/*
Strdup()
 Duplicate given string by allocating memory and performing
a string copy.

Return: pointer to newly duplicated string
*/

char *
Strdup(char *string)

{
  char *ptr;
  int len;

  assert(string != 0);

  /*
   * Add 1 to len for terminating \0
   */
  len = strlen(string) + 1;

  ptr = (char *) MyMalloc(len);
  return (Strncpy(ptr, string, len));
} /* Strdup() */
