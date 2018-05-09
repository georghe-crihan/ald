/*
 * libOFF
 *
 * Copyright (C) 2003 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: symbols.c,v 1.1.1.1 2004/04/26 00:40:33 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "symbols.h"

static struct aSymbol *createSYM(struct symbolWorkspace *ws);

/*
initSYM()
  Initialize a symbol workspace

Inputs: none

Return: pointer to new workspace
*/

struct symbolWorkspace *
initSYM()

{
  struct symbolWorkspace *ws;

  ws = (struct symbolWorkspace *) malloc(sizeof(struct symbolWorkspace));
  if (!ws)
  {
    fprintf(stderr,
            "initSYM: malloc failed: %s\n",
            strerror(errno));
    return (0);
  }

  memset(ws, '\0', sizeof(struct symbolWorkspace));

  return (ws);
} /* initSYM() */

/*
termSYM()
  Terminate a symbol workspace

Inputs: ws - workspace to terminate
*/

void
termSYM(struct symbolWorkspace *ws)

{
  if (!ws)
    return;

  unloadSYM(ws);

  free(ws);
} /* termSYM() */

/*
addSYM()
  Add a symbol to our symbol data structure

Inputs: data - symbol data element

Return: none
*/

void
addSYM(struct symbolWorkspace *ws, void *data)

{
  struct aSymbol *ptr;
  
  ptr = createSYM(ws);
  if (!ptr)
    return;

  ptr->data = data;

  ++(ws->numSymbols);
} /* addSYM() */

/*
traverseSYM()
  Traverse the symbol data structure and execute a function at
each node until the function returns ST_STOP

Inputs: ws    - symbol workspace
        func  - function to execute for each node - the "data"
                element of the node is passed to the function
        param - parameter passed to function in addition to "data"

Return: if func returns ST_STOP, return the data at the node
        at which we stopped

        0 otherwise
*/

void *
traverseSYM(struct symbolWorkspace *ws,
            int (*func)(void *data, void *arg),
            void *param)

{
  struct aSymbol *sptr;
  int ret;

  for (sptr = ws->symbolList; sptr; sptr = sptr->next)
  {
    ret = (*func)(sptr->data, param);
    if (ret == ST_STOP)
      return (sptr->data);
  }

  return (0);
} /* traverseSYM() */

/*
unloadSYM()
  Free memory associated with ws->symbolList

Inputs: ws - symbol workspace

Return: none
*/

void
unloadSYM(struct symbolWorkspace *ws)

{
  struct aSymbol *sptr;

  while (ws->symbolList)
  {
    sptr = ws->symbolList->next;
    free(ws->symbolList);
    ws->symbolList = sptr;
  }

  ws->numSymbols = 0;
} /* unloadSYM() */

/***********************************
 *       INTERNAL ROUTINES         *
 ***********************************/

/*
createSYM()
  Allocate space for a new symbol entry in our symbol data structure
and insert it into the structure

Inputs: ws - symbol workspace

Return: pointer to new symbol node
*/

static struct aSymbol *
createSYM(struct symbolWorkspace *ws)

{
  struct aSymbol *ptr;

  ptr = (struct aSymbol *) malloc(sizeof(struct aSymbol));
  if (!ptr)
  {
    fprintf(stderr,
            "createSYM: malloc failed: %s\n",
            strerror(errno));
    return (0);
  }

  ptr->next = ws->symbolList;
  ws->symbolList = ptr;

  return (ptr);
} /* createSYM() */
