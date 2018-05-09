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
 * $Id: input.c,v 1.1.1.1 2004/04/26 00:40:51 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "input.h"

/*
 * libString includes
 */
#include "Strn.h"

/*
 * Local: chain of command inputs
 */
static struct Input             *InputChain = 0;

/*
 * Local: pointer to last node in InputChain
 */
static struct Input             *InputChainEnd = 0;

/*
 * Local: pointer to current input node
 */
static struct Input             *CurrentInput = 0;

/*
AddInput()
  Add given input string to our input chain and return a pointer
to the newly allocated node
*/

struct Input *
AddInput(char *input)

{
  struct Input *ptr;

  ptr = (struct Input *) malloc(sizeof(struct Input));
  if (!ptr)
  {
    fprintf(stderr,
            "AddInput: malloc failed: %s\n",
            strerror(errno));
    return (0);
  }

  memset(ptr, 0, sizeof(struct Input));

  ptr->input = Strdup(input);

  ptr->prev = 0;
  ptr->next = InputChain;
  if (ptr->next)
    ptr->next->prev = ptr;

  InputChain = ptr;

  if (!InputChainEnd)
    InputChainEnd = ptr;

  /*
   * When the user requests the last input, we want to return
   * 'ptr' since it was inserted in the beginning of the InputChain,
   * so assign CurrentInput to ptr.
   */
  CurrentInput = ptr;

  return (ptr);
} /* AddInput() */

/*
DeleteInput()
  Delete given Input structure from InputChain
*/

void
DeleteInput(struct Input *ptr)

{
  if (ptr->next)
    ptr->next->prev = ptr->prev;
  else
    InputChainEnd = ptr->prev;

  if (ptr->prev)
    ptr->prev->next = ptr->next;
  else
    InputChain = ptr->next;

  free(ptr->input);
  free(ptr);
} /* DeleteInput() */

/*
GetPrevInput()
  Find the last command that the user typed and return a pointer
to it.
*/

char *
GetPrevInput()

{
  char *ret = 0;

  if (CurrentInput)
  {
    if (CurrentInput->next)
    {
      CurrentInput = CurrentInput->next;
      ret = CurrentInput->input;
    }
    else if (InputChain)
    {
      /*
       * We have reached the end of the chain, start over
       * from the beginning
       */
      CurrentInput = InputChain;
      ret = CurrentInput->input;
    }
  }

  return (ret);
} /* GetPrevInput() */

/*
GetPostInput()
  Opposite of GetPrevInput() - instead of going forward in
InputChain, go backward. This function is normally called when
the down arrow key is pressed.
*/

char *
GetPostInput()

{
  char *ret = 0;

  if (CurrentInput)
  {
    if (CurrentInput->prev)
    {
      CurrentInput = CurrentInput->prev;
      ret = CurrentInput->input;
    }
    else if (InputChainEnd)
    {
      /*
       * We have reached the first node in the chain - start
       * over from the end
       */
      CurrentInput = InputChainEnd;
      ret = CurrentInput->input;
    }
  }

  return (ret);
} /* GetPostInput() */
