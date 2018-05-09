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
 * $Id: disassemble.c,v 1.5 2004/10/10 03:07:56 pa33 Exp $
 */

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "alddefs.h"
#include "defs.h"
#include "disassemble.h"
#include "load.h"
#include "main.h"
#include "print.h"
#include "set.h"

#include "libDebug.h"
#include "libOFF.h"

/*
Disassemble()
  Backend for c_disassemble() - call the appropriate libDASM
routines to disassemble instructions from the file we are
debugging (this routine disassembles exactly 1 instruction)

Inputs: ws      - ald workspace
        data    - opcode to disassemble
        address - memory address of opcodes
        owin    - window to print disassembled instruction to

Return: number of bytes disassembled
        -1 if error occurred
*/

long
Disassemble(struct aldWorkspace *ws, unsigned char *data,
            unsigned int address, unsigned int owin)

{
  int ii;
  char buffer[MAXLINE];          /* buffer result is stored in */
  char mcode[MAXLINE];           /* buffer containing opcodes */
  int mlen;
  long length;                   /* length of opcode we disassembled */
  int sret;                      /* return value from findSymbolOFF() */
  struct offSymbolInfo symInfo;  /* symbol info */
  char sbuf[MAXLINE];            /* symbol buffer */
  char *bufptr;                  /* pointer into buffer */

  *buffer = '\0';

  length = procDisasm(ws->disasmWorkspace_p, data, buffer, address);
  if (length < 0)
  {
    Print(ws,
          P_COMMAND,
          "Disassembly error at offset 0x%08x: %s",
          address,
          buffer);
    return (-1);
  }

  if (length == 0)
  {
    /*
     * A length of 0 means we have encountered an unknown
     * instruction - output a message and keep going.
     */
    Print(ws,
          P_COMMAND,
          "Unknown instruction at offset 0x%08x: 0x%02X",
          address,
          (unsigned char) *data);

    sprintf(mcode, "%02X", (unsigned char) *data++);
    sprintf(buffer, "???");

    /*
     * Set length to 1 to update the offsets in order to get to
     * the next instruction
     */
    length = 1;
  }
  else
  {
    /*
     * Now advance data 'length' bytes - also store the machine
     * code along the way
     */
    mlen = 0;
    for (ii = 0; ii < length; ++ii)
    {
      sprintf(mcode + mlen, "%02X", (unsigned char) *data++);
      mlen += 2;
    }
  }

  /*
   * Check if this address corresponds to a function
   */

  *sbuf = '\0';
  if (IsSetDisasmShowSyms(ws))
  {
    sret = findSymbolOFF(ws->offWorkspace_p,
                         0,
                         address,
                         &symInfo);
    if (sret)
    {
      if (symInfo.offset)
        sprintf(sbuf, ":<%s+0x%x>", symInfo.name, symInfo.offset);
      else
        sprintf(sbuf, ":<%s>", symInfo.name);
    }
  }

  /*
   * Check if this instruction had a relative operand, and if so,
   * output the effective address and any symbol which might
   * contain it.
   */
  if (ws->disasmWorkspace_p->effectiveAddress > 0)
  {
    bufptr = buffer + strlen(buffer);

    sret = findSymbolOFF(ws->offWorkspace_p,
                         0,
                         ws->disasmWorkspace_p->effectiveAddress,
                         &symInfo);
    if (sret)
    {
      if (symInfo.offset)
      {
        bufptr += sprintf(bufptr,
                          " (0x%x:%s+0x%x)",
                          ws->disasmWorkspace_p->effectiveAddress,
                          symInfo.name,
                          symInfo.offset);
      }
      else
      {
        bufptr += sprintf(bufptr,
                          " (0x%x:%s)",
                          ws->disasmWorkspace_p->effectiveAddress,
                          symInfo.name);
      }
    } /* if (sret) */
    else
    {
      /* No matching symbol found */
      bufptr += sprintf(bufptr,
                        " (0x%x)",
                        ws->disasmWorkspace_p->effectiveAddress);
    }
  }

  /*
   * Output disassembled instruction
   */
  Print(ws,
        owin,
        "%08X%-20s  %-20s %-26s",
        address,
        sbuf,
        mcode,
        buffer);

  return (length);
} /* Disassemble() */

/*
DisplayNextInstruction()
  Called when the debugged process has stopped for whatever reason -
disassemble and output the next instruction to be executed.

Inputs: ws - ald workspace

Return: none
*/

void
DisplayNextInstruction(struct aldWorkspace *ws)

{
  unsigned char *codeptr;
  long ndumped;

  ws->nextInstruction = getAddressDebug(ws->debugWorkspace_p);

  /*
   * If in console mode, we don't have a window of the
   * next instructions, so disassemble the very next
   * instruction and display it
   */

  fputc('\n', stdout);

  codeptr = 0;

  /*
   * 20 bytes should be more than ample to grap one opcode
   */
  ndumped = dumpMemoryDebug(ws->debugWorkspace_p,
                            &codeptr,
                            ws->nextInstruction,
                            20);

  assert(codeptr != 0);

  if (ndumped == 0)
  {
    Print(ws,
          P_COMMAND,
          "Error disassembling next instruction (address: 0x%08lX)",
          ws->nextInstruction);
  }
  else
  {
    Disassemble(ws,
                codeptr,
                ws->nextInstruction,
                P_DEBUG);
  }

  free(codeptr);
} /* DisplayNextInstruction() */
