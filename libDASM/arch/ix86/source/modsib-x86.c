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
 * $Id: modsib-x86.c,v 1.1.1.1 2004/04/26 00:40:18 pa33 Exp $
 *
 * This module contains routines used to process/lookup ModR/M
 * and SIB byte information.
 */

/*
 * Some general info on ModR/M and SIB bytes to remind myself
 * from time to time:
 *
 * A ModR/M byte is constructed as follows:
 *
 * Bits: 7 6           5 4 3         2 1 0
 *       Mod           Reg/Opcode    R/M
 *
 * Mod        = Combines with the R/M field
 *
 * Reg/Opcode = Either a register number or three more bits
 *              of opcode information
 *
 * R/M        = Either a register or combines with Mod to form
 *              an effective address
 *
 * A SIB byte is constructed in the following manner:
 *
 * Bits:  7 6          5 4 3         2 1 0
 *        Scale        Index         Base
 *
 * Scale = A number (0-3) that you must raise 2 to in order to
 *         determine the scaling factor
 *
 * Index = A number (0-7) which tells you the effective address
 *         of the SIB byte. I have placed these values in SibTable[].
 *
 * Base  = A number (0-7) which tells you the register to use as
 *         the base register. I have placed these registers in
 *         x86SibBaseRegisters[].
 */

#include <stdio.h>
#include <assert.h>

#include "common-x86.h"
#include "modsib-x86.h"
#include "operands-x86.h"

/*
 * Top-level includes
 */

#include "libDASM.h"

static struct x86ModAddrInfo *x86getModAddress(struct disasmWorkspace *ws,
                                               unsigned char mod,
                                               unsigned char reg,
                                               unsigned char rm);
static unsigned int x86getModSibDisplacement(unsigned char *data, int numBytes);
static int x86hasEffectiveOperand(struct x86OpCode *opPtr);

/*
 * This corresponds to table 2-1 in the IAS, Vol 2. The first
 * index corresponds to the mod field. The second index corresponds
 * to the r/m field.
 */
static struct x86ModAddrInfo x86ModTable16[MAX_MOD][MAX_RM] = {

  /* MOD = 0 */

  {
    { M_BX_SI, 0 },
    { M_BX_DI, 0 },
    { M_BP_SI, 0 },
    { M_BP_DI, 0 },
    { M_SI, 0 },
    { M_DI, 0 },
    { M_NONE, MF_DISP16 },
    { M_BX, 0 }
  },

  /* MOD = 1 */

  {
    { M_BX_SI, MF_DISP8 },
    { M_BX_DI, MF_DISP8 },
    { M_BP_SI, MF_DISP8 },
    { M_BP_DI, MF_DISP8 },
    { M_SI, MF_DISP8 },
    { M_DI, MF_DISP8 },
    { M_BP, MF_DISP8 },
    { M_BX, MF_DISP8 }
  },

  /* MOD = 2 */

  {
    { M_BX_SI, MF_DISP16 },
    { M_BX_DI, MF_DISP16 },
    { M_BP_SI, MF_DISP16 },
    { M_BP_DI, MF_DISP16 },
    { M_SI, MF_DISP16 },
    { M_DI, MF_DISP16 },
    { M_BP, MF_DISP16 },
    { M_BX, MF_DISP16 }
  },

  /*
   * MOD = 3
   *
   * When mod is 3, the r/m field specifies a register rather
   * than a memory address. The actual register depends on
   * the bit size of the operand, so we cannot encode it here.
   * The determination of the actual register will be made later
   * when we construct the arguments. ie: if we come across
   * an operand r/m8 with a ModR/M byte with a mod of 3, we will
   * use an 8 bit register, which will be uniquely determined with
   * the r/m value.
   */

  {
    { -1, MF_REGISTER },
    { -1, MF_REGISTER },
    { -1, MF_REGISTER },
    { -1, MF_REGISTER },
    { -1, MF_REGISTER },
    { -1, MF_REGISTER },
    { -1, MF_REGISTER },
    { -1, MF_REGISTER }
  }
};

/*
 * This corresponds to table 2-2 in the IAS, Vol 2. The first
 * index corresponds to the mod field. The second index corresponds
 * to the r/m field.
 */
static struct x86ModAddrInfo x86ModTable32[MAX_MOD][MAX_RM] = {

  /* MOD = 0 */

  {
    { M_EAX, 0 },
    { M_ECX, 0 },
    { M_EDX, 0 },
    { M_EBX, 0 },
    { M_NONE, MF_SIB },
    { M_NONE, MF_DISP32 },
    { M_ESI, 0 },
    { M_EDI, 0 }
  },

  /* MOD = 1 */

  {
    { M_EAX, MF_DISP8 },
    { M_ECX, MF_DISP8 },
    { M_EDX, MF_DISP8 },
    { M_EBX, MF_DISP8 },
    { M_NONE, MF_SIB|MF_DISP8 },
    { M_EBP, MF_DISP8 },
    { M_ESI, MF_DISP8 },
    { M_EDI, MF_DISP8 }
  },

  /* MOD = 2 */

  {
    { M_EAX, MF_DISP32 },
    { M_ECX, MF_DISP32 },
    { M_EDX, MF_DISP32 },
    { M_EBX, MF_DISP32 },
    { M_NONE, MF_SIB|MF_DISP32 },
    { M_EBP, MF_DISP32 },
    { M_ESI, MF_DISP32 },
    { M_EDI, MF_DISP32 }
  },

  /*
   * MOD = 3
   *
   * When mod is 3, the r/m field specifies a register rather
   * than a memory address. The actual register depends on
   * the bit size of the operand, so we cannot encode it here.
   * The determination of the actual register will be made later
   * when we construct the arguments. ie: if we come across
   * an operand r/m8 with a ModR/M byte with a mod of 3, we will
   * use an 8 bit register, which will be uniquely determined with
   * the r/m value.
   */

  {
    { -1, MF_REGISTER },
    { -1, MF_REGISTER },
    { -1, MF_REGISTER },
    { -1, MF_REGISTER },
    { -1, MF_REGISTER },
    { -1, MF_REGISTER },
    { -1, MF_REGISTER },
    { -1, MF_REGISTER }
  }
};

/*
 * The following x86ModRegisters*[] arrays are used when the ModR/M
 * byte specifies a register instead of a memory address. This
 * occurs when we are dealing with r8/r16/r32 operands or with
 * rm8/rm16/rm32 operands with a MOD of 3 (see above)
 */

static int x86ModRegisters8[] = {
  M_AL,
  M_CL,
  M_DL,
  M_BL,
  M_AH,
  M_CH,
  M_DH,
  M_BH
};

static int x86ModRegisters16[] = {
  M_AX,
  M_CX,
  M_DX,
  M_BX,
  M_SP,
  M_BP,
  M_SI,
  M_DI
};

static int x86ModRegisters32[] = {
  M_EAX,
  M_ECX,
  M_EDX,
  M_EBX,
  M_ESP,
  M_EBP,
  M_ESI,
  M_EDI
};

/*
 * All possible address offsets for ModR/M bytes: this array
 * is indexed by the M_xxx values
 */
static char *x86ModAddrOffsets[] = {
  "ah",
  "al",
  "ax",
  "bh",
  "bl",
  "bp",
  "bx",
  "bp+di",
  "bp+si",
  "bx+di",
  "bx+si",
  "ch",
  "cl",
  "cx",
  "dh",
  "di",
  "dl",
  "dx",
  "eax",
  "ebp",
  "ebx",
  "ecx",
  "edi",
  "edx",
  "esi",
  "esp",
  "mm0",
  "mm1",
  "mm2",
  "mm3",
  "mm4",
  "mm5",
  "mm6",
  "mm7",
  "si",
  "sp",
  "xmm0",
  "xmm1",
  "xmm2",
  "xmm3",
  "xmm4",
  "xmm5",
  "xmm6",
  "xmm7",
  ""        /* M_NONE */
};

/*
 * This array corresponds to table 2-3 in the IAS, Vol 2.
 * We need to store less information than in the ModR/M case
 * because there are only 8 possible memory offsets. Only
 * the scale factor changes as we go to higher values of the
 * SIB byte.
 */
struct x86ModAddrInfo x86SibTable[1][8] = {
  {
    { M_EAX, 0 },
    { M_ECX, 0 },
    { M_EDX, 0 },
    { M_EBX, 0 },
    { M_NONE, 0 },
    { M_EBP, 0 },
    { M_ESI, 0 },
    { M_EDI, 0 }
  }
};

/*
 * SIB base registers - indexed by 'base' field of SIB byte
 */
static char *x86SibBaseRegisters[] = {
  "eax",
  "ecx",
  "edx",
  "ebx",
  "esp",
  "ebp",
  "esi",
  "edi"
};

/*
x86processModSib()
  Called from x86findOpCode() when a prospective match requires a
ModR/M (and possibly a SIB) byte. This routine makes sure the
byte in the actual opcode data stream is a valid ModR/M byte for
the given prospective match. If so, it then computes the address(es)
and displacements specified by the ModR/M (and SIB) byte(s).

Inputs: ws     - disasm workspace
        data   - actual opcode data we are trying to disassemble: it
                 should point to the ModR/M byte
        opPtr  - pointer to prospective opcode match
        msinfo - where to store ModR/M and SIB information

Prerequisites: ws->prefixFlags must reflect whether we are in 16 or 32 bit
               mode before calling this routine

Return: Upon success, total number of bytes in the ModR/M (and SIB) portion
        of opcode. This includes the ModR/M byte, the SIB byte (if any) and
        any displacement bytes, if any.

        Upon failure, -1.

Side effects: On success, 'msinfo' is modified to point to the correct
              ModR/M information.
*/

int
x86processModSib(struct disasmWorkspace *ws, unsigned char *data,
                 struct x86OpCode *opPtr, struct x86ModSibInfo *msinfo)

{
  unsigned char modrm;      /* ModR/M byte */
  unsigned char mod,        /* MOD portion of ModR/M byte */
                reg,        /* REG portion of ModR/M byte */
                rm;         /* R/M portion of ModR/M byte */
  unsigned char sib;        /* SIB byte */
  unsigned char scale,      /* scale portion of SIB byte */
                index,      /* index portion of SIB byte */
                base;       /* base portion of SIB byte */
  int bytes;                /* number of bytes in ModR/M, SIB portion of opcode */
  int hasEffectiveOperand;  /* does instruction need to compute effective address? */
  struct x86ModAddrInfo *modptr;
  struct x86ModAddrInfo *sibptr;

  bytes = 1;

  /*
   * Get the ModR/M byte
   */
  modrm = *data;

  /*
   * Strip off the MOD, REG, and R/M fields
   */
  mod = modrm >> 6;
  reg = (modrm >> 3) & 0x07;
  rm = modrm & 0x07;

  if ((opPtr->digit != REGRM) && (opPtr->digit != reg))
  {
    /*
     * Opcodes defined with /digit must have the REG portion
     * of their ModR/M byte equal to "digit". This prospective
     * match does not so it is a bad match.
     */
    return (-1);
  }

  modptr = x86getModAddress(ws, mod, reg, rm);
  if (!modptr)
    return (-1); /* error */

  msinfo->disp = 0;

  sib = 0;
  scale = 0;
  index = 0;
  base = 0;
  sibptr = 0;

  hasEffectiveOperand = x86hasEffectiveOperand(opPtr);

  if (hasEffectiveOperand)
  {
    /*
     * Only compute SIB bytes and displacements if this opcode
     * has an operand which requires an effective address. Otherwise
     * we will end up returning an incorrect byte count. An example
     * instruction which has a ModR/M byte but no rm/mem operand is
     * psllw.
     */

    if (modptr->flags & MF_SIB)
    {
      /*
       * The instruction we are disassembling contains a SIB byte
       */
      sib = *(data + 1);
      ++bytes;

      scale = sib >> 6;
      index = (sib >> 3) & 0x07;
      base = sib & 0x07;

      sibptr = &x86SibTable[0][index];

      if ((base == 5) && (mod == 0))
      {
        /*
         * This is the special case labelled by [*] in
         * table 2-3 of IAS. If base is 5 and mod is 0,
         * a 32 bit displacement follows the SIB byte.
         */
        msinfo->disp = x86getModSibDisplacement(data + bytes, 4);
        bytes += 4;
      }
    }

    if (modptr->flags & MF_DISP8)
    {
      msinfo->disp = x86getModSibDisplacement(data + bytes, 1);
      bytes += 1;
    }
    else if (modptr->flags & MF_DISP16)
    {
      msinfo->disp = x86getModSibDisplacement(data + bytes, 2);
      bytes += 2;
    }
    else if (modptr->flags & MF_DISP32)
    {
      msinfo->disp = x86getModSibDisplacement(data + bytes, 4);
      bytes += 4;
    }
  } /* if (hasEffectiveOperand) */

  msinfo->modptr = modptr;
  msinfo->modrm = modrm;
  msinfo->mod = mod;
  msinfo->reg = reg;
  msinfo->rm = rm;

  msinfo->sibptr = sibptr;
  msinfo->sib = sib;
  msinfo->scale = scale;
  msinfo->index = index;
  msinfo->base = base;

  return (bytes);
} /* x86processModSib() */

/*
x86getModAddrStr()
  Look up a ModR/M address offset in our string table

Inputs: index - index into x86ModAddrOffsets[] (M_xxx)

Return: address string corresponding to mptr
*/

char *
x86getModAddrStr(int index)

{
  assert((index >= 0) && (index <= M_NONE));

  return (x86ModAddrOffsets[index]);
} /* x86getModAddrStr() */

/*
x86getModRegister()
  This routine is called when we are looking for a register specified
by a ModR/M byte. This can happen two ways:

1. We get an r8/r16/r32 operand, in which case the register is specified
   by the REG field of the ModR/M byte.

2. We get an rm8/rm16/rm32/mm/m64 operand with a MOD field of 3, in which case
   the register is specified by the RM field of the ModR/M byte.

Inputs: index - either REG (for case 1) or RM (for case 2)
        flags - bitmask containing operand size information (BITSXX)

Return: pointer to string containing corresponding register
*/

char *
x86getModRegister(unsigned char index, unsigned int flags)

{
  int idx;

  assert(index <= 7);

  if (flags & BITS8)
    idx = x86ModRegisters8[index];
  else if (flags & BITS16)
    idx = x86ModRegisters16[index];
  else if (flags & BITS32)
    idx = x86ModRegisters32[index];
  else if (flags & BITS64)
    idx = M_MM0 + index;
  else if (flags & REG_MMX)
    idx = M_MM0 + index;
  else if (flags & REG_XMM)
    idx = M_XMM0 + index;
  else
  {
    fprintf(stderr, "x86getModRegister: warning: defaulting to 16 bits\n");
    idx = x86ModRegisters16[index];
  }

  return (x86ModAddrOffsets[idx]);
} /* x86getModRegister() */

/*
x86getSibBaseRegister()
  Lookup a SIB base register

Inputs: base - base portion of SIB byte

Return: register string
*/

char *
x86getSibBaseRegister(unsigned char base)

{
  assert(base <= 7);

  return (x86SibBaseRegisters[base]);
} /* x86getSibBaseRegister() */

/*********************************************************
 *                  INTERNAL ROUTINES                    *
 *********************************************************/

/*
x86getModAddress()
  This routine searches x86ModTableXX[] to find the address offset
for a given ModR/M byte.

Inputs: ws  - disasm workspace
        mod - mod portion of ModR/M byte
        reg - reg portion of ModR/M byte
        rm  - r/m portion of ModR/M byte

Return: pointer to correct entry in x86ModTableXX[] upon success
        NULL upon failure
*/

static struct x86ModAddrInfo *
x86getModAddress(struct disasmWorkspace *ws, unsigned char mod,
                 unsigned char reg, unsigned char rm)

{
  struct x86ModAddrInfo *mptr;

  assert((mod <= 3) && (reg <= 7) && (rm <= 7));

  mptr = 0;

  if (ws->flags & DA_16BITMODE)
  {
    if (ws->prefixFlags & PX_ADDROVER)
      mptr = &x86ModTable32[mod][rm];
    else
      mptr = &x86ModTable16[mod][rm];
  }
  else if (ws->flags & DA_32BITMODE)
  {
    if (ws->prefixFlags & PX_ADDROVER)
      mptr = &x86ModTable16[mod][rm];
    else
      mptr = &x86ModTable32[mod][rm];
  }
  else
  {
    fprintf(stderr,
            "x86getModAddress: error: we are neither in 16 nor 32 bit mode\n");
    return (0);
  }

  return (mptr);
} /* x86getModAddress() */

/*
x86getModSibDisplacement()
  Called when our ModR/M or SIB byte requires a displacement. The
displacement can be 8, 16, or 32 bits. This routine reads off
the displacement and returns it.

Inputs: data     - string containing displacement
        numBytes - number of bytes in displacement

Return: displacement
*/

static unsigned int
x86getModSibDisplacement(unsigned char *data, int numBytes)

{
  unsigned int disp;
  int len;
  unsigned long factor;

  assert(numBytes <= 4);

  disp = 0;
  len = 0;

  /*
   * XXX - this loop is little-endian specific
   */
  while (numBytes--)
  {
    /*
     * factor = 256^len
     */
    factor = 1 << (8 * len);
    disp += (unsigned char) data[len++] * factor;
  }

  return (disp);
} /* x86getModSibDisplacement() */

/*
x86hasEffectiveOperand()
  Some MMX instructions (psllw) are defined with a /digit but
do not have rm or mem operands and thus do not need to compute
effective addresses. Our routine x86processModSib() determines
any SIB bytes and displacements before operand processing, so
if we get a psllw with a ModR/M which specifies a displacement,
we don't want x86processModSib() to compute the displacement since
no operand needs it and thus it is ignored.

  This routine determines if any operands of opPtr require
the calculation of an effective address.

Inputs: opPtr - opcode match

Return: 1 if opPtr has an effective address operand
        0 if not
*/

static int
x86hasEffectiveOperand(struct x86OpCode *opPtr)

{
  int ii;

  for (ii = 0; ii < opPtr->OperandCount; ++ii)
  {
    if (opPtr->operands[ii] & (REGMEM | MEMORY))
      return (1);
  }

  return (0);
} /* x86hasEffectiveOperand() */
