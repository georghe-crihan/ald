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
 * $Id: prefix-x86.c,v 1.1.1.1 2004/04/26 00:40:09 pa33 Exp $
 */

#include <stdio.h>
#include <assert.h>

#include "regs-x86.h"
#include "prefix-x86.h"
#include "operands-x86.h"

/*
 * Top-level includes
 */

#include "libDASM.h"

/*
 * If any of these bytes follow a REP (0xF3) prefix, use
 * REPE instead of REP
 */
int prefixREPE[] = {
  0xA6,
  0xA7,
  0xAE,
  0xAF,
  (-1)
};

/*
x86processPrefix()
  Called from x86findOpCode() to determine if there is a prefix
in front of the opcode being disassembled. If so, toggle the
correct flags in ws->prefixFlags.

Inputs: ws   - disasm workspace
        data - buffer containing opcode

Return: number of bytes in prefix
*/

unsigned char
x86processPrefix(struct disasmWorkspace *ws, unsigned char *data)

{
  unsigned char numBytes;
  int done;
  unsigned char byte;

  assert(ws && data);

  numBytes = 0;
  done = 0;

  while (!done)
  {
    byte = *data++;

    switch (byte)
    {
      /*
       * Indicates operand size override. If in 16 bit mode,
       * instructions with 32 bit operands will be chosen over
       * those with 16 bit operands. If in 32 bit mode, instructions
       * with 16 bit operands will be chosen over those with 32
       * bit operands.
       */
      case 0x66:
      {
        ws->prefixFlags |= PX_OPOVER;
        ++numBytes;

        break;
      } /* case 0x66 */

      /*
       * Addressing size override. If in 16 bit mode, 32 bit addressing
       * will be used and vice versa.
       */
      case 0x67:
      {
        ws->prefixFlags |= PX_ADDROVER;
        ++numBytes;

        break;
      } /* case 0x67 */

      /*
       * lock prefix
       */
      case 0xF0:
      {
        ws->prefixFlags |= PX_LOCK;
        ++numBytes;

        break;
      } /* case 0xF0 */

      /*
       * Indicates a REPNE (repeat while not equal) prefix
       */
      case 0xF2:
      {
        /*
         * If we have an "F2 0F ..." situation, the F2 is
         * not a prefix but part of the opcode of an SSE
         * instruction.
         */
        if (*data == 0x0F)
        {
          done = 1;
          break;
        }

        ws->prefixFlags |= PX_REPNE;
        ++numBytes;

        break;
      } /* case 0xF2 */

      /*
       * Indicates a REP or REPE prefix
       */
      case 0xF3:
      {
        int *tmp;
        unsigned int flag;

        /*
         * If we have an "F3 0F ..." situation, the F3 is
         * not a prefix but part of the opcode of an SSE
         * instruction.
         */
        if (*data == 0x0F)
        {
          done = 1;
          break;
        }

        flag = PX_REP;
        for (tmp = prefixREPE; *tmp != (-1); ++tmp)
        {
          if ((unsigned int) *data == (unsigned int) *tmp)
            flag = PX_REPE;
        }

        ws->prefixFlags |= flag;
        ++numBytes;

        break;
      } /* case 0xF3 */

      /*
       * Segment overrides
       */

      case 0x2E:        /* cs */
      {
        ws->prefixFlags |= PX_SEGOVER;
        ws->segmentOverride = R_CS;
        ++numBytes;

        break;
      } /* case 0x2E */

      case 0x36:        /* ss */
      {
        ws->prefixFlags |= PX_SEGOVER;
        ws->segmentOverride = R_SS;
        ++numBytes;

        break;
      } /* case 0x36 */

      case 0x3E:        /* ds */
      {
        ws->prefixFlags |= PX_SEGOVER;
        ws->segmentOverride = R_DS;
        ++numBytes;

        break;
      } /* case 0x3E */

      case 0x26:        /* es */
      {
        ws->prefixFlags |= PX_SEGOVER;
        ws->segmentOverride = R_ES;
        ++numBytes;

        break;
      } /* case 0x26 */

      case 0x64:        /* fs */
      {
        ws->prefixFlags |= PX_SEGOVER;
        ws->segmentOverride = R_FS;
        ++numBytes;

        break;
      } /* case 0x64 */

      case 0x65:        /* gs */
      {
        ws->prefixFlags |= PX_SEGOVER;
        ws->segmentOverride = R_GS;
        ++numBytes;

        break;
      } /* case 0x65 */

      default:
      {
        done = 1;
        break;
      }
    } /* switch (byte) */
  } /* while (!done) */

  return (numBytes);
} /* x86processPrefix() */

/*
x86testPrefix()
  Called from x86findOpCode() to determine if a potential match passes
prefix requirements, such as operand override.

Inputs: ws  - disasm workspace
        ptr - potential opcode match

Return: 0 if ptr does not pass prefix test
        1 if ptr passes prefix test but there is a possibility of
          a better match
        2 if ptr passes all prefix tests with no possibility of a
          better match
*/

int
x86testPrefix(struct disasmWorkspace *ws, struct x86OpCode *ptr)

{
  unsigned int flags;

  assert(ptr != 0);

  /*
   * Our goal here is to determine what bit mode this
   * instruction wants to be in. For example, we may
   * be disassembling the file in 16 bit mode, but if
   * this instruction has an operand override prefix,
   * we need to disassemble it in 32 bit mode. The
   * operand override prefix is a toggle between 16
   * and 32 bit mode. The requirements here are as
   * follows:
   *
   * 1. If we are in 16 bit mode, an operand override prioritizes
   *    the 32 bit version of the same instruction, if there is one.
   *    If there is not, the 16 bit version is still acceptable. An
   *    example of this is the NOP instruction. There is only one
   *    NOP (0x90) so an opcode of the form (0x66 0x90) should also
   *    be a NOP since there is no "32 bit" version of NOP.
   * 2. If we are in 32 bit mode, an operand override tells us to
   *    use the 16 bit version of the instruction.
   */

  flags = 0;
  if (ws->flags & DA_16BITMODE)
  {
    if (ws->prefixFlags & PX_OPOVER)
      flags = DA_32BITMODE;
    else
      flags = DA_16BITMODE;
  }
  else if (ws->flags & DA_32BITMODE)
  {
    if (ws->prefixFlags & PX_OPOVER)
      flags = DA_16BITMODE;
    else
      flags = DA_32BITMODE;
  }
  else
  {
    fprintf(stderr,
            "x86testPrefix: error: we are neither in 16 nor 32 bit mode\n");
    return (0);
  }

  if (flags & DA_16BITMODE)
  {
    /*
     * The instruction wants to be disassembled in 16
     * bit mode: if any of the prospective match's operands
     * is 32 bits, declare it to be a weak match.
     */
    if ((ptr->operands[0] & BITS32) ||
        (ptr->operands[1] & BITS32) ||
        (ptr->operands[2] & BITS32))
      return (1);
  }
  else if (flags & DA_32BITMODE)
  {
    /*
     * The instruction wants to be disassembled in 32
     * bit mode. If this prospective match has no 32
     * bit operands, declare it to be a weak match:
     * there may be another prospective down the line
     * with a 32 bit operand, but if there is not, this
     * prospective could still be used.
     */
    if (!(ptr->operands[0] & BITS32) &&
        !(ptr->operands[1] & BITS32) &&
        !(ptr->operands[2] & BITS32))
      return (1);
  }
  else
  {
    fprintf(stderr,
            "x86testPrefix: error: flags variable is empty\n");
    return (0);
  }

  return (2);
} /* x86testPrefix() */

/*
x86addrSizeAttribute()
  Determine the address size attribute of the current
instruction we are disassembling.

Inputs: ws - disasm workspace

Return: DA_16BITMODE or DA_32BITMODE depending on the size attributes
        of the instruction
*/

unsigned int
x86addrSizeAttribute(struct disasmWorkspace *ws)

{
  if (ws->flags & DA_16BITMODE)
  {
    if (ws->prefixFlags & PX_ADDROVER)
      return (DA_32BITMODE);
    else
      return (DA_16BITMODE);
  }
  else if (ws->flags & DA_32BITMODE)
  {
    if (ws->prefixFlags & PX_ADDROVER)
      return (DA_16BITMODE);
    else
      return (DA_32BITMODE);
  }

  /*
   * We should never get here: default to 32 bit mode
   */
  fprintf(stderr,
          "x86addrSizeAttribute: error: we are neither in 16 nor 32 bit mode\n");

  return (DA_32BITMODE);
} /* x86addrSizeAttribute() */
