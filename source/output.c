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
 * $Id: output.c,v 1.1.1.1 2004/04/26 00:40:49 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "alddefs.h"
#include "main.h"
#include "misc.h"

/*
BoolPrompt()
  Continue to display a prompt until a boolean answer is received

Inputs: prompt - prompt string to display

Return: 1 if input is yes
        0 if input is no
*/

int
BoolPrompt(char *prompt)

{
  int val = (-1);
  char buffer[MAXLINE];

  assert(prompt != 0);

  while (val == (-1))
  {
    fputs(prompt, stdout);
    fgets(buffer, sizeof(buffer), stdin);
    val = StrToBool(buffer);
  }

  return (val);
} /* BoolPrompt() */

/*
NumPrompt()
  Display a prompt asking for an integer value and read in
the value

Inputs: prompt - prompt string to display
        err    - set to 1 if error encountered

Return: numerical answer input

Side effects: if the value entered into the prompt is an
              invalid number, 'err' is set to 1

NOTE: Unlike BoolPrompt, the prompt is displayed only once, so
      they have only one shot to enter a valid input
*/

unsigned long
NumPrompt(char *prompt, int *err)

{
  /*
   * This must be unsigned long for c_enter() - so it can handle
   * large 32 bit numbers
   */
  unsigned long ret = 0;
  char buffer[MAXLINE];
  char *endptr;
  size_t nread;

  assert(prompt && err);

  fputs(prompt, stdout);
  fgets(buffer, sizeof(buffer), stdin);
  nread = strlen(buffer);
  if (buffer[nread - 1] == '\n')
    buffer[nread - 1] = '\0';

  ret = strtoul(buffer, &endptr, 0);

  if ((endptr == buffer) || (*endptr != '\0'))
    *err = 1; /* invalid input */

  return (ret);
} /* NumPrompt() */
