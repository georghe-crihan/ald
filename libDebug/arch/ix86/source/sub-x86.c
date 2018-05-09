/*
 * libDebug
 *
 * Copyright (C) 2000 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: sub-x86.c,v 1.2 2004/09/11 05:17:16 pa33 Exp $
 */

#include "sub-x86.h"

static struct OpSub SubOpcodes[] = {
  { 0xE8, -1, 5 },
  { 0xFF, 2, 2 },
  { 0x9A, -1, 7 },
  { 0xFF, 3, 2 },

  { 0, 0, 0 }
};

/*
IsSubroutine()
  Determine if the first few bytes of 'buf' correspond to a CALL
instruction, indicating we are about to enter a subroutine.

Return: 0 if it is not a subroutine, or the number of bytes in the
        opcode if it is
*/

int
IsSubroutine(unsigned char *buf)

{
  unsigned char first;
  struct OpSub *optr;

  first = *buf++;
  for (optr = SubOpcodes; optr->oplen; ++optr)
  {
    if (first == optr->byte)
    {
      if (optr->digit != (-1))
      {
        unsigned char reg;

        /*
         * This opcode expects a ModR/M digit - make sure it
         * matches the next byte of 'buf'
         */
        reg = (*buf >> 3) & 0x07;
        if (reg != optr->digit)
          continue; /* bad match */
      }

      /*
       * Good match
       */
      return (optr->oplen);
    }
  }

  return (0);
} /* IsSubroutine() */
