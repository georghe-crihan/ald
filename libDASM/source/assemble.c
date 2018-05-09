/*
 * libDASM
 *
 * Copyright (C) 2000-2003 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: assemble.c,v 1.1.1.1 2004/04/26 00:40:29 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "assemble.h"

/*
initAsm()
  Initialize asm workspace

Inputs: flags - flags bitmask (DA_xxx): useful for specifying
                whether we are assembling in 16 or 32 bit mode

Return: pointer to new workspace, or NULL if failed
*/

struct asmWorkspace *
initAsm(unsigned int flags)

{
  struct asmWorkspace *ws;

  ws = (struct asmWorkspace *) malloc(sizeof(struct asmWorkspace));
  if (!ws)
  {
    fprintf(stderr, "initAsm: malloc failed: %s\n", strerror(errno));
    return (0);
  }

  memset(ws, '\0', sizeof(struct asmWorkspace));

  ws->flags = flags;

  return (ws);
} /* initAsm() */

/*
termAsm()
  Terminate asm workspace
*/

void
termAsm(struct asmWorkspace *ws)

{
  if (!ws)
    return;

  free(ws);
} /* termAsm() */

/*
flagsAsm()
  Change assembler flags

Inputs: ws    - asm workspace
        flags - new flags (DA_xxx)

Return: none
*/

void
flagsAsm(struct asmWorkspace *ws, unsigned int flags)

{
  ws->flags = flags;
} /* flagsAsm() */

/*
procAsm()
  Call the appropriate assembler routine for the platform we are using
with the given arguments. One instruction is assembled for each call
of this function.

Inputs: ws     - workspace
        str    - string containing instruction
        outbuf - buffer to store resulting opcode

Return: number of bytes assembled
        Upon an error, -1 is returned and an error message is stored
        in 'outbuf'
*/

int
procAsm(struct asmWorkspace *ws, char *str, unsigned char *outbuf)

{
#ifdef INTEL86

  return (x86procAsm(ws, str, outbuf));

#else

  return (0);

#endif
} /* procAsm() */
