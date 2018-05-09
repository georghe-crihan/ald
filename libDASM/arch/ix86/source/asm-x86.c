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
 * $Id: asm-x86.c,v 1.1.1.1 2004/04/26 00:40:11 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <assert.h>

#include "asm-x86.h"
#include "inames-x86.h"
#include "operands-x86.h"
#include "optab-x86.h"
#include "regs-x86.h"

/*
 * Top-level includes
 */

#include "assemble.h"
#include "libDASM.h"

static int parseInstructionAsm(char *buf,
                               struct instructionInfo *info);
static int findInstructionAsm(struct instructionInfo *insInfo,
                              struct x86OpCode **match,
                              char *errstr);
static int x86isConstantAsm(char *str, struct immediateInfo *immInfo);
static int matchOperandsAsm(struct instructionInfo *ins,
                            struct x86OpCode *match,
                            int num, char *errstr);
static int binarySearchAsm(char *needle, const char **haystack,
                           int n);

/*
x86procAsm()
  Assemble one x86 instruction

Inputs: ws     - asm workspace
        str    - buffer containing instruction
        outbuf - where to store resulting opcode

Return: length of 'outbuf' upon success
        -1 upon error (error goes in outbuf)
*/

int
x86procAsm(struct asmWorkspace *ws, char *str,
           unsigned char *outbuf)

{
  struct instructionInfo insInfo;
  struct x86OpCode *match;
  int ret;
  char buffer[MAXLINE];

  strncpy(buffer, str, MAXLINE - 1);

  memset((void *) &insInfo, '\0', sizeof(struct instructionInfo));

  /*
   * Determine if we have a valid instruction: if so
   * put name/operand stuff in insInfo
   */
  ret = parseInstructionAsm(buffer, &insInfo);
  if (ret < 0)
  {
    sprintf((char *) outbuf,
            "x86procAsm: parse error:%d: %s",
            -ret,
            str);
    return (-1);
  }
  else if (ret == 0)
  {
    sprintf((char *) outbuf,
            "x86procAsm: invalid instruction: %s",
            str);
    return (-1);
  }

  /*
   * If we get here, we have a valid instruction name
   * with at most 3 operands
   */
  printf("[%s]\n", str);
  for (ret = 0; ret < insInfo.opnum; ++ret)
  {
    if (insInfo.operands[ret] & REGISTER)
    {
      printf("  operand %d = [%s] (register)\n",
             ret + 1,
             x86RegistersDASM[insInfo.opinfo[ret]].name);
    }
    else if (insInfo.operands[ret] & IMMEDIATE)
    {
      if (insInfo.hasImmed)
      {
        printf("  operand %d = [%lx] (constant)\n",
          ret + 1,
          insInfo.immInfo.inum);
      }
    }
  }

  ret = findInstructionAsm(&insInfo, &match, (char *)outbuf);
  if (ret <= 0)
    return (ret);

  /*
   * We have a matching instruction
   */

  ret = 0;

  /*
   * Store opcode into outbuf
   */
  strncpy((char *) outbuf, match->mcode, match->oplen);
  ret += match->oplen;
  outbuf += match->oplen;

  /*
   * Store immediate byte(s) into outbuf: the size
   * attributes of the immediate bytes will have been
   * filled in by findInstructionAsm()
   */
  if (insInfo.immInfo.flags != 0)
  {
    /*
     * XXX - this is little endian specific
     */
    if (insInfo.immInfo.flags & DASM_IMMED_BITS8)
    {
      /*
       * The 0xFF is unnecessary but I'm paranoid
       */
      *outbuf++ = (unsigned char) insInfo.immInfo.inum & 0xFF;
      ret += 1;
    }
    else if (insInfo.immInfo.flags & DASM_IMMED_BITS16)
    {
      *outbuf++ = (unsigned char) insInfo.immInfo.inum & 0xFF;
      *outbuf++ = (unsigned char) (insInfo.immInfo.inum >> 8) & 0xFF;
      ret += 2;
    }
    else if (insInfo.immInfo.flags & DASM_IMMED_BITS32)
    {
      *outbuf++ = (unsigned char) insInfo.immInfo.inum & 0xFF;
      *outbuf++ = (unsigned char) (insInfo.immInfo.inum >> 8) & 0xFF;
      *outbuf++ = (unsigned char) (insInfo.immInfo.inum >> 16) & 0xFF;
      *outbuf++ = (unsigned char) (insInfo.immInfo.inum >> 24) & 0xFF;
      ret += 4;
    }
    else
      assert(0);
  } /* if (insInfo.immInfo.flags != 0) */

  return (ret);
} /* x86procAsm() */

/*****************************************************
 *              INTERNAL ROUTINES                    *
 *****************************************************/

/*
parseInstructionAsm()
  Called from x86procAsm() to parse an instruction in
ascii form. Determine if the line is a valid instruction,
and isolate instruction name and operands.

Inputs: buf - buffer containing ascii instruction
        info - where to store resulting info

Return: Valid instruction: 1 (various values go into info)
        Invalid instruction name: 0
        Operand parse error: -<num>, where <num> is the position
          of 'buf' where parse error occurs
*/

static int
parseInstructionAsm(char *buf, struct instructionInfo *info)

{
  char *origbuf;                 /* original buffer */
  char *iname;                   /* name of instruction */
  int ret;
  int opcnt;                     /* number of operands */
  char *operands[3];             /* operands */
  struct immediateInfo immInfo;  /* numerical constant info */
  int ii;                        /* looping */
  unsigned int sizeflag;         /* size of instruction */

  origbuf = buf;

  /*
   * Eliminate any preceding whitespace
   */
  while (*buf && isspace(*buf))
    ++buf;

  if (!*buf)
    return (0); /* empty string */

  /*
   * Store location of instruction name
   */
  iname = buf;

  /*
   * Advance buf to the end of the instruction name
   */
  while (*buf && !isspace(*buf))
    ++buf;

  /*
   * Put in a '\0' to isolate instruction name
   */
  *buf++ = '\0';

  /*
   * Look for instruction in our list
   */
  ret = binarySearchAsm(iname,
                        x86InstructionNames,
                        NUM_ELEMENTS(x86InstructionNames));

  if (ret < 0)
    return (0); /* instruction not found */

  info->name = ret;

  /*
   * The instruction name is ok, now look at operands
   */

  opcnt = 0;

  while (*buf)
  {
    /*
     * Get rid of whitespace
     */
    while (*buf && isspace(*buf))
      ++buf;

    if (!*buf)
      break;

    if (*buf == ',')
    {
      if (!opcnt)
        return (-(buf - origbuf)); /* comma with no operand */

      *buf++ = '\0';

      while (*buf && isspace(*buf))
        ++buf;

      if (!*buf)
        break;
    }

    if (opcnt >= 3)
      return (-(buf - origbuf)); /* too many operands */

    operands[opcnt++] = buf;

    /*
     * Advance to the end of this operand
     */
    while (*buf && !isspace(*buf) && (*buf != ','))
      ++buf;

    /*
     * Set this character to \0 to isolate the operand
     */
    *buf++ = '\0';
  } /* while (*buf) */

  assert(opcnt <= 3);

  printf("INSTRUCTION: %s\n", iname);

  /*
   * We now have pointers to each operand. We will
   * now determine what types of operands we have
   */
  for (ii = 0; ii < opcnt; ++ii)
  {
    printf("operand %d = [%s]\n", ii, operands[ii]);

    if ((ret = x86findRegisterDASM(operands[ii])) >= 0)
    {
      /*
       * This operand is a register
       */
      info->operands[ii] = x86RegistersDASM[ret].flags;
      info->opinfo[ii] = ret;
    }
    else if ((ret = x86isConstantAsm(operands[ii], &immInfo)) >= 0)
    {
      /*
       * This operand is a numerical value (integer or float)
       */
      info->operands[ii] = IMMEDIATE;
      info->immInfo = immInfo;
      info->hasImmed = 1;
    }
  #if 0
    else if ((ret = x86isEffectiveAddressAsm()) >= 0)
    {
    }
  #endif
  }

  info->opnum = opcnt;

  return (1);
} /* parseInstructionAsm() */

/*
findInstructionAsm()
  This routine is called after parseInstructionAsm() to locate
a given instruction and verify it has correct operands.

Inputs: insInfo - various information about instruction provided by
                  parseInstructionAsm()
        match   - where to store match
        errstr  - where to store errors

Return: 1 if instruction is found (goes in match)
        0 if not
        -1 if error occurs (error goes in errstr)

Side effects: If instruction is found and has an immediate operand,
              the size attributes of insInfo->immInfo are filled in.
*/

static int
findInstructionAsm(struct instructionInfo *insInfo,
                   struct x86OpCode **match, char *errstr)

{
  struct x86OpCode *candidates;  /* instruction candidates */
  struct x86OpCode *iptr;        /* current instruction */
  struct x86OpCode *bestmatch;   /* best match */
  int ii;                        /* looping */
  int badMatch;                  /* bad match? */
  int ret;
  int opnum;                     /* operand number */

  /*
   * insInfo->name contains the I_xxx entry corresponding to
   * the instruction name.
   */
  candidates = x86Instructions[insInfo->name];

  /*
   * 'candidates' points to one of the Instruction_XXX
   * arrays which are arranged according to the name of
   * the instruction. We now need to find which one of
   * them matches their operands with insInfo.
   */
  for (iptr = candidates; iptr->name != (-1); ++iptr)
  {
    assert(iptr->name == insInfo->name);

    badMatch = 0;

    /*
     * Check if number of operands match
     */
    if (iptr->OperandCount != insInfo->opnum)
      continue; /* operand mismatch */

    /*
     * Loop through operands, checking if each one
     * matches up
     */
    for (ii = 0; ii < insInfo->opnum; ++ii)
    {
      ret = matchOperandsAsm(insInfo, iptr, ii, errstr);
      if (ret < 0)
        return (-1); /* error */
      else if (ret == 0)
      {
        badMatch = 1;
        break;
      }
    }

    if (badMatch)
      continue;

    /*
     * All operands match up
     */

    if (insInfo->immInfo.flags)
    {
      /*
       * The instruction we are assembling contains
       * immediate bytes - determine the size attributes
       * (ib/iw/id) from the matching instruction
       */

      opnum = -1;
      for (ii = 0; ii < iptr->OperandCount; ++ii)
      {
        if (iptr->operands[ii] & IMMEDIATE)
          opnum = ii;
      }

      if (opnum < 0)
      {
        sprintf(errstr,
                "findInstructionAsm: matching instruction has no immediate operand");
        return (-1);
      }

      /*
       * Fill in the appropriate immediate size so
       * later we can put it in the opcode
       */
      if (iptr->operands[opnum] & BITS32)
        insInfo->immInfo.flags |= DASM_IMMED_BITS32;
      else if (iptr->operands[opnum] & BITS16)
        insInfo->immInfo.flags |= DASM_IMMED_BITS16;
      else
      {
        assert(iptr->operands[opnum] & BITS8);
        insInfo->immInfo.flags |= DASM_IMMED_BITS8;
      }
    } /* if (insInfo->immInfo.flags) */

    *match = iptr;

    return (1);
  } /* for (iptr = candidates; iptr->name != (-1); ++iptr) */

  return (0);
} /* findInstructionAsm() */

/*
x86isConstantAsm()
  Determine whether an operand is a numerical constant (integer
or floating point).

Inputs: str       - string containing potential constant
        immInfo   - where to store immediate information

Return: 1 if str is a numerical constant (size goes in 'size')
        0 if not
*/

static int
x86isConstantAsm(char *str, struct immediateInfo *immInfo)

{
  long inum;
  char *endptr;

  inum = strtol(str, &endptr, 0);
  if ((endptr != str) && (*endptr == '\0'))
  {
    /*
     * It is a valid integer
     */
    immInfo->inum = inum;

    if (inum > 65535)
      immInfo->flags = DASM_IMMED_BITS32;
    else if (inum > 255)
      immInfo->flags = DASM_IMMED_BITS16;
    else
      immInfo->flags = DASM_IMMED_BITS8;

    return (1);
  }

  return (0);
} /* x86isConstantAsm() */

/*
matchOperandsAsm()
  Check if an operand for a potential match corresponds to
the operand for the instruction we are assembling.

Inputs: ins    - instruction we are assembling
        match  - potential match
        num    - operand number
        errstr - where to store errors

Return: 1 if operands match
        0 if not
        -1 upon error (error goes in errstr)
*/

static int
matchOperandsAsm(struct instructionInfo *ins, struct x86OpCode *match,
                 int num, char *errstr)

{
  unsigned int insop,   /* instruction operand */
               matchop; /* potential match operand */
  unsigned int mask;

  insop = ins->operands[num];
  matchop = match->operands[num];

  mask = 0;

  /*
   * Now attempt to identity the defining property of
   * our instruction's operand.
   */
  if (insop & REGISTER)
    mask = REGISTER;
  else if (insop & IMMEDIATE)
    mask = IMMEDIATE;
  else if (insop & REGMEM)
    mask = REGMEM;
  else if (insop & MEMORY)
    mask = MEMORY;

  /*
   * These guys override the above properties since it
   * is possible that insop will be REGISTER|REG_FPU
   * since it is defined that way in x86RegistersDASM[]
   */
  if (insop & REG_FPU)
    mask = REG_FPU;
  if (insop & REG_MMX)
    mask = REG_MMX;
  if (insop & REG_XMM)
    mask = REG_XMM;

  if (!mask)
  {
    sprintf(errstr,
            "matchOperandsAsm: operand does not have a well defined type");
    return (-1);
  }

  /*
   * The potential match's operand must match mask or
   * there is no match.
   */
  if (!(matchop & mask))
    return (0);

  /*
   * At this point the two operands are of the same type
   * (register/immediate/rm/memory/...). Now check size
   * attributes.
   */

  mask = 0;
  if (insop & BITS8)
    mask = BITS8;
  else if (insop & BITS16)
    mask = BITS16;
  else if (insop & BITS32)
    mask = BITS32;
  else if (insop & BITS64)
    mask = BITS64;
  else if (insop & BITS80)
    mask = BITS80;

  /*
   * Make sure potential match operand has same size attributes
   */
  if (mask && !(matchop & mask))
    return (0);

  return (1);
} /* matchOperandsAsm() */

/*
binarySearchAsm()
  Search an array of strings for a string. The array of strings
must be sorted alphabetically.

Inputs: needle   - what to look for
        haystack - where to search
        n        - number of elements in haystack

Return: index of haystack if element found
        -1 if not found
*/

static int
binarySearchAsm(char *needle, const char **haystack, int n)

{
  int i;
  int low,
      high,
      middle;

  low = (-1);
  high = n;

  while ((high - low) >= 2)
  {
    middle = (low + high) / 2;

    i = strcasecmp(needle, haystack[middle]);

    if (i < 0)
      high = middle;   /* it is below the middle */
    else if (i > 0)
      low = middle;    /* it is above the middle */
    else
      return (middle); /* we got a match */
  }

  return (-1);
} /* binarySearchAsm() */
