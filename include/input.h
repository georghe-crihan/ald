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
 * $Id: input.h,v 1.1.1.1 2004/04/26 00:41:12 pa33 Exp $
 */

#ifndef INCLUDED_input_h
#define INCLUDED_input_h

struct Input
{
  struct Input *next, *prev;
  char *input; /* input string */
};

/*
 * Prototypes
 */

struct Input *AddInput(char *input);
void DeleteInput(struct Input *ptr);
char *GetPrevInput();
char *GetPostInput();

#endif /* INCLUDED_input_h */
