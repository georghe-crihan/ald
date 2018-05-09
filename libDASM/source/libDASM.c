/*
 * libDASM
 *
 * Copyright (C) 2000-2003 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: libDASM.c,v 1.2 2004/08/31 02:24:50 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "libDASM.h"

/*
initDASM()
  Initialize a dasm workspace

Inputs: flags - DA_xxx

Return: pointer to new workspace
*/

struct dasmWorkspace *
initDASM(unsigned int flags)

{
  struct dasmWorkspace *ws;

  ws = (struct dasmWorkspace *) malloc(sizeof(struct dasmWorkspace));
  if (!ws)
  {
    fprintf(stderr,
            "initDASM: malloc failed: %s\n",
            strerror(errno));
    return (0);
  }

  memset(ws, '\0', sizeof(struct dasmWorkspace));

  ws->asmWorkspace_p = initAsm(flags);
  if (!ws->asmWorkspace_p)
  {
    termDASM(ws);
    return (0);
  }

  ws->disasmWorkspace_p = initDisasm(flags);
  if (!ws->disasmWorkspace_p)
  {
    termDASM(ws);
    return (0);
  }

  return (ws);
} /* initDASM() */

/*
termDASM()
  Terminate a dasm workspace

Inputs: ws - workspace to terminate

Return: none
*/

void
termDASM(struct dasmWorkspace *ws)

{
  if (!ws)
    return;

  if (ws->asmWorkspace_p)
    termAsm(ws->asmWorkspace_p);

  if (ws->disasmWorkspace_p)
    termDisasm(ws->disasmWorkspace_p);

  free(ws);
} /* termDASM() */

/*
assembleDASM()
  Assemble one instruction

Inputs: ws     - dasm workspace
        str    - string containing instruction
        outbuf - where to store opcode

Return: length of 'outbuf' upon success
        -1 upon error (error goes in outbuf)
*/

int
assembleDASM(struct dasmWorkspace *ws, char *str,
             unsigned char *outbuf)

{
  return (procAsm(ws->asmWorkspace_p, str, outbuf));
} /* assembleDASM() */

/*
disassembleDASM()
  Disassemble one instruction

Inputs: ws      - dasm workspace
        data    - opcode data stream
        outbuf  - where to store result
        address - address of where this instruction is located
                  in the file or memory we are diassembling; when
                  given, relative addresses (such as in a CALL)
                  will be added to this address to give an exact
                  target address.

Return: number of bytes disassembled upon success
        -1 upon error (error message goes in outbuf)
*/

long
disassembleDASM(struct dasmWorkspace *ws, unsigned char *data,
                char *outbuf, unsigned int address)

{
  return (procDisasm(ws->disasmWorkspace_p, data, outbuf, address));
} /* disassembleDASM() */
