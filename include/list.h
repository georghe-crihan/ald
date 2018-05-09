/*
 * Assembly Language Debugger
 *
 * Copyright (C) 2000-2003 Patrick Alken
 * This program comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: list.h,v 1.1.1.1 2004/04/26 00:41:11 pa33 Exp $
 */

#ifndef INCLUDED_list_h
#define INCLUDED_list_h

struct genericList
{
  struct genericList *prev, *next;
  void *ptr;
};

/*
 * Prototypes
 */

struct genericList *insertList(struct genericList **list, void *data);
void deleteList(struct genericList **list, struct genericList *ptr);
void freeList(struct genericList **list);

#endif /* INCLUDED_list_h */
