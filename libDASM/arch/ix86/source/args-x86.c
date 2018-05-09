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
 * $Id: args-x86.c,v 1.3 2004/09/02 00:11:59 pa33 Exp $
 *
 * This module is used by the disassembler to construct the argument
 * string for a particular opcode.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "args-x86.h"
#include "common-x86.h"
#include "inames-x86.h"
#include "operands-x86.h"
#include "prefix-x86.h"
#include "regs-x86.h"

/*
 * Top-level includes
 */

#include "libDASM.h"

static char *x86operandRegister(struct x86matchInfo *ptr, int opnum,
                                char *errstr);
static int x86operandEffectiveAddress(struct disasmWorkspace *ws,
                                      struct x86matchInfo *ptr,
                                      unsigned int operand, char *str);
static int x86operandSegOff(unsigned char **data, unsigned int operand,
                            char *str);
static int x86operandMemoryOffset(struct disasmWorkspace *ws,
                                  unsigned char **data,
                                  char *str);
static unsigned long x86getImmediate(unsigned char **data,
                                     unsigned int flags, int *err);

/*
 * The following x86RegisterCodesXX[] tables correspond to table 3.1
 * in the Intel Architecture Software Developer's Manual, Vol 2. They
 * are used to determine the register specified by a +rb/+rw/+rd
 * code added to the last byte of an opcode. The value added
 * to the last opcode byte is between 0 and 7, and indexes these
 * tables to get the correct register.
 */

/* +rb - 8 bit register operand */
static int x86RegisterCodes8[] = {
  R_AL,
  R_CL,
  R_DL,
  R_BL,
  R_AH,
  R_CH,
  R_DH,
  R_BH
};

/* +rw - 16 bit register operand */
static int x86RegisterCodes16[] = {
  R_AX,
  R_CX,
  R_DX,
  R_BX,
  R_SP,
  R_BP,
  R_SI,
  R_DI
};

/* +rd - 32 bit register operand */
static int x86RegisterCodes32[] = {
  R_EAX,
  R_ECX,
  R_EDX,
  R_EBX,
  R_ESP,
  R_EBP,
  R_ESI,
  R_EDI
};

static char *x86SegmentRegisters[] = {
  "es",
  "cs",
  "ss",
  "ds",
  "fs",
  "gs",
  "?s",
  "?s"
};

/*
x86constructArguments()
  Construct the correct arguments for the instruction 'ptr'.

Inputs: ws      - disasm workspace
        data    - data buffer containing instruction we are
                  disassembling
        ptr     - instruction matching 'data'
        outbuf  - where to store arguments
        address - address of this instruction in the file or memory
                  we are currently disassembling; when given,
                  relative addresses (such as in a CALL or JMP)
                  will be added to this address to calculate
                  an exact target address.

Return: 1 upon success
        0 upon failure (error message goes in outbuf)

Side effects: On success, outbuf will contain instruction name and arguments
              On failure, outbuf will contain error message

              'data' variable may be advanced due to reading of immediate bytes,
              modrm bytes, etc
*/

int
x86constructArguments(struct disasmWorkspace *ws, unsigned char **data,
                      struct x86matchInfo *ptr, char *outbuf,
                      unsigned int address)

{
  int ii;                   /* looping */
  struct x86OpCode *opPtr;  /* opcode pointer */
  char tmpbuf[MAXLINE];     /* temporary buffer */
  char *origout;            /* original outbuf */
  long bias;                /* eip relative address bias */

  assert(data && *data && ptr && outbuf);

  /*
   * bias is initialized to the 2's compliment of the instruction's
   * actual address in the buffer.  We do this to compute the
   * size of the instruction by adding the new value of *data.
   * The resulting equation is this:
   *
   * bias = NEW_data_addr - OLD_data_addr
   *
   * which is precisely what we want.
   *
   * Note the [-1] subscript of the character array reference is
   * to compensate for the fact that the instruction's opcode has
   * already been "fetched" by the disassembly engine.
   *
   * --2004aug30 saf2
   *
   * The purpose of this is for relative operands which are
   * defined relative to the instruction after the current
   * instruction. In order to compute an exact address, we
   * need to know the size of the current opcode. This bias
   * variable is set to that size in the section below on
   * relative operands.
   *
   * -- Patrick Alken
   */

  bias = -((unsigned long)(&((*data)[-1])));

  opPtr = ptr->opPtr;
  origout = outbuf;

  if (ws->prefixFlags & PX_LOCK)
    outbuf += sprintf(outbuf, "%s", "lock ");
  else if (ws->prefixFlags & PX_REP)
    outbuf += sprintf(outbuf, "%s", "rep ");
  else if (ws->prefixFlags & PX_REPE)
    outbuf += sprintf(outbuf, "%s", "repe ");
  else if (ws->prefixFlags & PX_REPNE)
    outbuf += sprintf(outbuf, "%s", "repne ");

  /*
   * Write instruction name to outbuf
   */
  outbuf += sprintf(outbuf, "%s", x86InstructionNames[opPtr->name]);

  /*
   * Loop through operands and add them to outbuf
   */
  for (ii = 0; ii < opPtr->OperandCount; ++ii)
  {
    if (ii == 0)
      *outbuf++ = ' ';
    else
    {
      *outbuf++ = ',';
      *outbuf++ = ' ';
    }

    if (opPtr->operands[ii] & NEAR)
      outbuf += sprintf(outbuf, "near ");
    else if (opPtr->operands[ii] & FAR)
      outbuf += sprintf(outbuf, "far ");
    else if (opPtr->operands[ii] & SHORT)
      outbuf += sprintf(outbuf, "short ");

    if (opPtr->operands[ii] & (REGISTER | REG_MMX | REG_XMM))
    {
      char *regstr;

      /*
       * We have a register operand - determine which register
       * and print it to outbuf
       */
      regstr = x86operandRegister(ptr,
                                  ii,
                                  tmpbuf);

      if (regstr)
        outbuf += sprintf(outbuf, "%s", regstr);
      else
      {
        strcpy(origout, tmpbuf);
        return (0); /* error */
      }
    } /* if (opPtr->operands[ii] & (REGISTER | REG_MMX | REG_XMM)) */
    else if (opPtr->operands[ii] & IMMEDIATE)
    {
      unsigned long value;
      int err;

      err = 0;
      value = x86getImmediate(data,
                              opPtr->operands[ii],
                              &err);

      if (err)
      {
        sprintf(origout,
                "x86constructArguments: x86getImmediate failed for instruction: %s",
                x86InstructionNames[opPtr->name]);
        return (0);
      }

      outbuf += sprintf(outbuf, "0x%lx", value);
    } /* if (opPtr->operands[ii] & IMMEDIATE) */
    else if (opPtr->operands[ii] & (REGMEM | MEMORY))
    {
      int ret;

      /*
       * We have an rm8/rm16/rm32 operand
       */

      ret = x86operandEffectiveAddress(ws,
                                       ptr,
                                       opPtr->operands[ii],
                                       tmpbuf);

      if (ret >= 0)
        outbuf += sprintf(outbuf, "%s", tmpbuf);
      else
      {
        strcpy(origout, tmpbuf);
        return (0); /* error */
      }
    } /* if (opPtr->operands[ii] & (REGMEM | MEMORY)) */
    else if (opPtr->operands[ii] & RELATIVE)
    {
      unsigned long value;
      int err;

      /*
       * Relative operands (rel8/16/32) are bytes following
       * the opcode specifying a relative address
       */

      err = 0;
      value = x86getImmediate(data,
                              opPtr->operands[ii],
                              &err);

      if (err)
      {
        sprintf(origout,
                "x86constructArguments: x86getImmediate failed for instruction: %s",
                x86InstructionNames[opPtr->name]);
        return (0);
      }

      /*
       * Note: this code was contributed by Samuel Falvo II
       * <kc5tja =at= arrl net>
       */
      bias += (unsigned long) (*data);
      if ((unsigned char) *(opPtr->mcode) == 0x0F)
      {
        /* two-byte branch */
        bias++;
      }

      outbuf += sprintf(outbuf, "+0x%lx", value);

      /*
       * Store the exact target address in ws->effectiveAddress
       * so that the calling program can use it to look up
       * symbols/functions corresponding to this relative
       * address.
       */
      ws->effectiveAddress = address + value + bias;
    } /* if (opPtr->operands[ii] & RELATIVE) */
    else if (opPtr->operands[ii] & SEG16)
    {
      int ret;

      /*
       * This operand is ptr16:16 or ptr16:32.
       * This means we need an expression of the form
       * segment:offset, where segment is the number of bits on
       * the left of the colon, and offset is the number of bits
       * on the right.
       */

      ret = x86operandSegOff(data, opPtr->operands[ii], tmpbuf);

      if (ret >= 0)
        outbuf += sprintf(outbuf, "%s", tmpbuf);
      else
      {
        strcpy(origout, tmpbuf);
        return (0); /* error */
      }
    } /* if (opPtr->operands[ii] & SEG16) */
    else if (opPtr->operands[ii] & REG_FPU)
    {
      /*
       * Floating point stack register
       */
      assert(ptr->fpucode >= 0);
      assert(ptr->fpucode <= 7);

      outbuf += sprintf(outbuf,
                        "%s",
                        x86RegistersDASM[R_ST0 + ptr->fpucode].name);
    } /* if (opPtr->operands[ii] & REG_FPU) */
    else if (opPtr->operands[ii] & REG_SR)
    {
      /*
       * We have an Sreg operand (segment register). The REG
       * field of the ModR/M byte specifies which register to use.
       * According to IAS, Vol 2, the values of the segment registers
       * are as follows:
       *
       * ES = 0
       * CS = 1
       * SS = 2
       * DS = 3
       * FS = 4
       * GS = 5
       */

      outbuf += sprintf(outbuf,
                        "%s",
                        x86SegmentRegisters[ptr->msinfo.reg]);
    } /* if (opPtr->operands[ii] & REG_SR) */
    else if (opPtr->operands[ii] & REG_CONTROL)
    {
      /*
       * According to IAS, Vol 2. the REG field of the ModR/M
       * byte specifies the control register
       */

      outbuf += sprintf(outbuf,
                        "%s",
                        x86RegistersDASM[R_CR0 + ptr->msinfo.reg].name);
    } /* if (opPtr->operands[ii] & REG_CONTROL) */
    else if (opPtr->operands[ii] & REG_DEBUG)
    {
      /*
       * According to IAS, Vol 2. the REG field of the ModR/M
       * byte specifies the debug register
       */

      outbuf += sprintf(outbuf,
                        "%s",
                        x86RegistersDASM[R_DR0 + ptr->msinfo.reg].name);
    } /* if (opPtr->operands[ii] & REG_DEBUG) */
    else if (opPtr->operands[ii] & MEMOFFS)
    {
      int ret;

      /*
       * We have a moffs8/16/32 operand. This is a 16 or 32 bit
       * offset (depending on the size attributes of the instruction)
       * which comes after the opcode. The 8/16/32 following the moffs
       * specify the size of the data at the offset location.
       */

      ret = x86operandMemoryOffset(ws, data, tmpbuf);

      if (ret >= 0)
        outbuf += sprintf(outbuf, "%s", tmpbuf);
      else
      {
        strcpy(origout, tmpbuf);
        return (0); /* error */
      }
    } /* if (opPtr->operands[ii] & MEMOFFS) */
    else if (opPtr->operands[ii] & CONSTANT)
    {
      /*
       * The operand is a numerical constant whose value
       * is stored in opinfo[ii]
       */
      assert(opPtr->opinfo[ii] != NOOPARG);
      outbuf += sprintf(outbuf, "%d", opPtr->opinfo[ii]);
    } /* if (opPtr->operands[ii] & CONSTANT) */
  } /* for (ii = 0; ii < opPtr->OperandCount; ++ii) */

  *outbuf = '\0';

  return (1);
} /* x86constructArguments() */

/*
x86operandRegister()
  Handle a register operand (r8/r16/r32/mm/xmm)

Inputs: ptr     - opcode pointer
        opnum   - number of current operand (first, second, etc)
        errstr  - where to store errors

Return: pointer to string containing matching register upon success
        NULL upon error

Side effects: Upon failure, an error message goes in errstr
*/

static char *
x86operandRegister(struct x86matchInfo *ptr, int opnum, char *errstr)

{
  struct x86OpCode *opPtr;
  unsigned int operand;
  int regindex;

  opPtr = ptr->opPtr;
  operand = opPtr->operands[opnum];

  /*
   * First check if it is a specific register (R_AL etc). This
   * occurs in instructions like ADC where a specific register
   * is encoded into the instruction.
   */
  if ((operand & REGISTER) && (opPtr->opinfo[opnum] != NOOPARG))
  {
    if (opPtr->opinfo[opnum] < 0)
    {
      sprintf(errstr,
              "x86operandRegister: bad operand info\n");
      return (0);
    }

    if (opPtr->opinfo[opnum] == MODFIELD_RM)
      return (x86getModRegister(ptr->msinfo.rm, operand));
    else
      return (x86RegistersDASM[opPtr->opinfo[opnum]].name);
  }

  if (opPtr->digit == REGRM)
  {
    /*
     * This instruction is defined with a /r as well as a
     * register operand. The register for this operand
     * is determined by the REG field of the ModR/M byte.
     */
    assert(ptr->msinfo.modptr != 0);

    return (x86getModRegister(ptr->msinfo.reg, operand));
  } /* if (opPtr->digit == REGRM) */
  else if ((opPtr->digit >= 0) && (opPtr->digit <= 7))
  {
    if ((operand & REG_MMX) || (operand & REG_XMM))
    {
      /*
       * We got a mm or xmm operand
       */
      return (x86getModRegister(ptr->msinfo.rm, operand));
    }
    else
    {
      /*
       * We got an r8/r16/r32 operand. We should never get here: /digit
       * opcodes always have rm8/rm16/rm32/mm/xmm operands, never r8/r16/r32
       * operands.
       */
      sprintf(errstr,
              "x86operandRegister: error: we got a /digit with a register operand");
      return (0);
    }
  }
  else if (opPtr->digit == REGCODE)
  {
    /*
     * This instruction is defined with a +rb/+rw/+rd code
     * indicating something was added to the last byte of
     * the opcode which specifies a register. This added
     * value is stored in ptr->regcode (from x86findOpCode)
     */
    assert(ptr->regcode >= 0);
    assert(ptr->regcode <= 7);

    regindex = (-1);

    if (operand & BITS8)
      regindex = x86RegisterCodes8[ptr->regcode];
    else if (operand & BITS16)
      regindex = x86RegisterCodes16[ptr->regcode];
    else if (operand & BITS32)
      regindex = x86RegisterCodes32[ptr->regcode];

    if (regindex < 0)
    {
      sprintf(errstr,
              "x86operandRegister: invalid register operand for instruction %s (%ld)",
              x86InstructionNames[opPtr->name],
              opPtr->operands[opnum]);
      return (0);
    }

    return (x86RegistersDASM[regindex].name);
  } /* if (opPtr->digit == REGCODE) */

  return (0);
} /* x86operandRegister() */

/*
x86operandEffectiveAddress()
  This routine handles the following operands (which all require
effective address computations from ModR/M bytes):

rm8
rm16
rm32
m8
m16
m32
m64
m128
xmm?/m*

Inputs: ws      - disasm workspace
        ptr     - opcode pointer
        operand - operand flags
        str     - where to store register or address

Return: -1 upon failure: error message goes in 'str'
        1 upon success
*/

static int
x86operandEffectiveAddress(struct disasmWorkspace *ws,
                           struct x86matchInfo *ptr,
                           unsigned int operand,
                           char *str)

{
  char *origstr;
  char *tmpstr;

  assert(ptr->msinfo.modptr);

  origstr = str;

  if (ptr->msinfo.mod == 3)
  {
    /*
     * Special case: ModR/M bytes C0 -> FF are ambiguous. That is,
     * their effective addresses can be one of five registers -
     * we can determine the correct register by looking at the
     * operand's size attribute. Also, we don't have to worry about
     * SIB bytes since any ModR/M bytes with a "mod" of 3 have
     * no SIBs.
     */

    tmpstr = x86getModRegister(ptr->msinfo.rm, operand);
    if (!tmpstr)
    {
      sprintf(origstr,
              "x86operandEffectiveAddress: x86getModRegister failed");
      return (-1);
    }

    str += sprintf(str, "%s", tmpstr);

    return (1);
  }

  /*
   * The r/m operand specifies a memory location, not a register:
   * we need to calculate the effective address.
   */

  if (operand & BITS8)
    str += sprintf(str, "byte ");
  else if (operand & BITS16)
    str += sprintf(str, "word ");
  else if (operand & BITS32)
    str += sprintf(str, "dword ");
  else if (operand & BITS64)
    str += sprintf(str, "qword ");
  else if (operand & BITS80)
    str += sprintf(str, "tword "); /* FPU */

  /*
   * It is a memory location: use []'s :)
   */
  *str++ = '[';

  if (ws->prefixFlags & PX_SEGOVER)
  {
    assert(ws->segmentOverride != (-1));
    str += sprintf(str, "%s:", x86RegistersDASM[ws->segmentOverride].name);
  }

  if (ptr->msinfo.modptr->flags & MF_SIB)
  {
    /*
     * Write the base register to str: there is one case
     * where there is no base register (base = 5, mod = 0) -
     * see table 2-3 of IAS.
     */
    if (!((ptr->msinfo.base == 5) && (ptr->msinfo.mod == 0)))
    {
      tmpstr = x86getSibBaseRegister(ptr->msinfo.base);
      str += sprintf(str, "%s", tmpstr);

      if (ptr->msinfo.sibptr->index != M_NONE)
        *str++ = '+';
    }

    /*
     * Get the index address
     */
    if (ptr->msinfo.sibptr->index != M_NONE)
    {
      tmpstr = x86getModAddrStr(ptr->msinfo.sibptr->index);
      if (!tmpstr)
      {
        sprintf(origstr,
                "x86operandEffectiveAddress: x86getModAddrStr failed");
        return (-1);
      }

      str += sprintf(str, "%s", tmpstr);

      if (ptr->msinfo.scale > 0)
        str += sprintf(str, "*%d", 1 << ptr->msinfo.scale);
    }
  } /* if (ptr->msinfo.modptr->flags & MF_SIB) */
  else
  {
    tmpstr = x86getModAddrStr(ptr->msinfo.modptr->index);
    if (!tmpstr)
    {
      sprintf(origstr,
              "x86operandEffectiveAddress: x86getModAddrStr failed");
      return (-1);
    }

    str += sprintf(str, "%s", tmpstr);
  }

  /*
   * Add any displacements
   */
  if (ptr->msinfo.disp)
    str += sprintf(str, "+0x%x", ptr->msinfo.disp);

  *str++ = ']';
  *str = '\0';

  return (1);
} /* x86operandEffectiveAddress() */

/*
x86operandSegOff()
  This routine handles the operands ptr16:16 or ptr16:32,
which are of the form segment:offset, where segment is the number of bits
on the left of the colon, and offset is the number of bits on the right.

Inputs: data    - opcode data stream
        operand - flags for this operand
        str     - argument string (or error string)

Return: 1 upon success (argument goes in str)
        0 upon failure (error goes in str)
*/

static int
x86operandSegOff(unsigned char **data, unsigned int operand, char *str)

{
  int err;
  unsigned long segment,
                offset;

  err = 0;
  if (operand & OFF16)
    offset = x86getImmediate(data, BITS16, &err);
  else if (operand & OFF32)
    offset = x86getImmediate(data, BITS32, &err);
  else
  {
    sprintf(str,
            "x86operandSegOff: offset operand is neither 16 nor 32 bits");
    return (0);
  }

  if (err)
  {
    sprintf(str,
            "x86operandSegOff: x86getImmediate failed");
    return (0);
  }

  segment = x86getImmediate(data, BITS16, &err);

  if (err)
  {
    sprintf(str,
            "x86operandSegOff: x86getImmediate failed");
    return (0);
  }

  sprintf(str, "0x%lx:0x%lx", segment, offset);

  return (1);
} /* x86operandSegOff() */

/*
x86operandMemoryOffset()
  This routine is called when we have a moffs8/16/32 operand.
The 8/16/32 refer to the size of the data at the offset. The offset
is a 16 or 32 bit value (depending on the size attributes of the
instruction) which follows the opcode.

Inputs: ws     - disasm workspace
        data   - opcode data stream
        str    - where to store result

Return: 1 upon success
        0 upon failure
*/

static int
x86operandMemoryOffset(struct disasmWorkspace *ws, unsigned char **data,
                       char *str)

{
  unsigned long value;
  int err;
  unsigned int sizeattr;

  err = 0;

  sizeattr = x86addrSizeAttribute(ws);
  if (sizeattr & DA_16BITMODE)
    value = x86getImmediate(data, BITS16, &err);
  else
    value = x86getImmediate(data, BITS32, &err);

  if (err)
  {
    sprintf(str,
            "x86operandMemoryOffset: x86getImmediate failed");
    return (0);
  }

  if (ws->prefixFlags & PX_SEGOVER)
  {
    assert(ws->segmentOverride != (-1));
    str += sprintf(str, "%s:", x86RegistersDASM[ws->segmentOverride].name);
  }

  sprintf(str, "[+0x%lx]", value);

  return (1);
} /* x86operandMemoryOffset() */

/*
x86getImmediate()
  Called when an operand has the IMMEDIATE bit set - obtain the
immediate byte value from 'data'

Inputs: data  - actual opcode data stream where immediate byte(s) are stored
        flags - bitmask variable containing size of immediate
                value
        err   - set to 1 if error occurs

Return: value of the immediate byte(s)
*/

static unsigned long
x86getImmediate(unsigned char **data, unsigned int flags, int *err)

{
  unsigned long ret;
  int length;

  ret = 0;
  length = 0;

  /*
   * Thank god for little endian :-)
   */

  if (flags & BITS8)
  {
    ret = (unsigned char) (*data)[length++];
    ++(*data);
  }
  else if (flags & BITS16)
  {
    ret = (unsigned char) (*data)[length++];
    ret += (unsigned char) (*data)[length++] * 256;
    (*data) += 2;
  }
  else if (flags & BITS32)
  {
    ret = (unsigned char) (*data)[length++];
    ret += (unsigned char) (*data)[length++] * 256;
    ret += (unsigned char) (*data)[length++] * 65536;
    ret += (unsigned char) (*data)[length++] * 16777216;
    (*data) += 4;
  }
  else
    *err = 1;

  return (ret);
} /* x86getImmediate() */
