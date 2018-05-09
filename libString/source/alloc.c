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
 * $Id: alloc.c,v 1.1.1.1 2004/04/26 00:40:54 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>

static void OutOfMemory();

/*
MyMalloc()
  Attempt to malloc 'bytes' bytes of memory; returns a pointer
to allocated memory if successful, otherwise calls OutOfMem()
*/

void *
MyMalloc(const size_t bytes)

{
  void *ptr;

  ptr = (void *) malloc(bytes);
  if (!ptr)
    OutOfMemory();

  return (ptr);
} /* MyMalloc() */

/*
MyRealloc()
 Call realloc() on the old pointer, with the new byte size
*/

void *
MyRealloc(void *old, const size_t bytes)

{
  void *new;

  new = (void *) realloc(old, bytes);
  if (!new)
    OutOfMemory();

  return (new);
} /* MyRealloc() */

static void
OutOfMemory()

{
  fprintf(stderr, "Out of Memory, exiting\n");
  exit(1);
} /* OutOfMemory() */
