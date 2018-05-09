/*
 * libString
 *
 * Copyright (C) 2000 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: alloc.h,v 1.1.1.1 2004/04/26 00:40:55 pa33 Exp $
 */

#ifndef INCLUDED_alloc_h
#define INCLUDED_alloc_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>        /* size_t */
#define INCLUDED_sys_types_h
#endif

#ifndef INCLUDED_stdlib_h
#include <stdlib.h>           /* free() */
#define INCLUDED_stdlib_h
#endif

#define MyFree(x)         \
  {                       \
    free((x));            \
    (x) = 0;              \
  }

/*
 * Prototypes
 */

void *MyMalloc(const size_t bytes);
void *MyRealloc(void *old, const size_t bytes);

#endif /* INCLUDED_alloc_h */
