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
 * $Id: list.c,v 1.1.1.1 2004/04/26 00:40:47 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "list.h"

static void unlinkList(struct genericList **list,
                       struct genericList *ptr);

/*
insertList()
  Insert an element into a linked list

Inputs: list - list to insert into
        data - data to insert

Return: pointer to new node
*/

struct genericList *
insertList(struct genericList **list, void *data)

{
  struct genericList *ptr;

  ptr = (struct genericList *) malloc(sizeof(struct genericList));
  if (!ptr)
  {
    fprintf(stderr,
            "insertList: malloc failed: %s\n",
            strerror(errno));
    return (0);
  }

  memset(ptr, 0, sizeof(struct genericList));

  ptr->ptr = data;

  ptr->prev = 0;
  ptr->next = *list;
  if (ptr->next)
    ptr->next->prev = ptr;

  *list = ptr;

  return (ptr);
} /* insertList() */

/*
deleteList()
  Delete a node from a list - does not free node's data

Inputs: list - linked list
        ptr  - node to delete

Return: none
*/

void
deleteList(struct genericList **list, struct genericList *ptr)

{
  if (!ptr)
    return;

  unlinkList(list, ptr);
  free(ptr);
} /* deleteList() */

/*
freeList()
  Free all node data in a given linked list, and delete list

Inputs: list - list to free

Return: none

Side effects: *list is set to NULL
*/

void
freeList(struct genericList **list)

{
  struct genericList *node;

  while (*list)
  {
    node = *list;
    
    /* free node data */
    free(node->ptr);

    *list = node->next;

    /* free node */
    free(node);
  }
} /* clearList() */

/*
unlinkList()
  Unlink a node from a list

Inputs: list - linked list
        ptr  - node to unlink

Return: none
*/

static void
unlinkList(struct genericList **list, struct genericList *ptr)

{
  assert(ptr != 0);

  if (ptr->next)
    ptr->next->prev = ptr->prev;

  if (ptr->prev)
    ptr->prev->next = ptr->next;
  else
    *list = ptr->next;
} /* unlinkList() */
