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
 * $Id: disassemble.c,v 1.2 2004/08/31 02:24:50 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "disassemble.h"

/*
initDisasm()
  Initialize disasm workspace

Inputs: flags - flags bitmask (DA_xxx): useful for specifying
                whether we are disassembling in 16 or 32 bit mode

Return: pointer to new workspace, or NULL if failed
*/

struct disasmWorkspace *
initDisasm(unsigned int flags)

{
  struct disasmWorkspace *ws;

  ws = (struct disasmWorkspace *) malloc(sizeof(struct disasmWorkspace));
  if (!ws)
  {
    fprintf(stderr, "initDisasm: malloc failed: %s\n", strerror(errno));
    return (0);
  }

  memset(ws, '\0', sizeof(struct disasmWorkspace));

  ws->flags = flags;

  ws->segmentOverride = (-1);

  return (ws);
} /* initDisasm() */

/*
termDisasm()
  Terminate disasm workspace
*/

void
termDisasm(struct disasmWorkspace *ws)

{
  if (!ws)
    return;

  free(ws);
} /* termDisasm() */

/*
flagsDisasm()
  Change disassembler flags

Inputs: ws    - disasm workspace
        flags - new flags (DA_xxx)

Return: none
*/

void
flagsDisasm(struct disasmWorkspace *ws, unsigned int flags)

{
  ws->flags = flags;
} /* flagsDisasm() */

/*
procDisasm()
  Call the appropriate disassemble routine for the platform we are using
with the given arguments. One instruction is disassembled for each call
of this function.

Inputs: ws      - workspace
        data    - data to be disassembled
        outbuf  - buffer to store disassembled result
        address - (optional) address of where this opcode is located
                  in the file or in memory. When given, relative
                  addresses (such as in a CALL) will be added to
                  this address to compute an exact target address.

Return: number of bytes disassembled
        Upon an error, -1 is returned and an error message is stored
        in 'outbuf'
*/

long
procDisasm(struct disasmWorkspace *ws, unsigned char *data,
           char *outbuf, unsigned int address)

{
#ifdef INTEL86

  return (x86procDisasm(ws, data, outbuf, address));

#else

  return (0);

#endif
} /* procDisasm() */
