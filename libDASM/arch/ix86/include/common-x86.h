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
 * $Id: common-x86.h,v 1.1.1.1 2004/04/26 00:40:23 pa33 Exp $
 *
 * This header file contains definitions common to both the
 * assembler and disassembler.
 */

#ifndef INCLUDED_common_x86_h
#define INCLUDED_common_x86_h

/*
 * This struct contains information on each x86 instruction
 * and is used to construct instruction/opcode tables used
 * by the assembler and disassembler.
 */

struct x86OpCode
{
  int name;           /* name of symbolic instruction */
  int OperandCount;   /* number of operands */
  long operands[3];   /* array containing operand types */
  char *mcode;        /* machine code the instruction assembles to */
  int oplen;          /* length of mcode - can't use strlen if \x00's */
  int digit;          /* ModR/M digit if there is one */
  /*
   *  This array is used to store extra information about registers
   * for each operand. Each index of this array corresponds to the
   * same index of operands[]. One use of this array is to represent
   * general registers such as "al". In these cases, the slot in
   * opinfo[] will be the index of Registers[] corresponding to
   * the register we want. Suppose operands[0] requires the al
   * register. It will have the REGISTER bit set, and opinfo[0]
   * will be set to R_AL.
   *  The second use of this array is for the instructions using
   * the control, debug, or fpu registers. If an operand specifically
   * needs fpu(1), it will have the REG_FPU bit set, and the
   * corresponding index of opinfo[] will be set to 1.
   */
  short opinfo[3];
};

/*
 * This is the value the indices of opinfo[] will take on if
 * there is no register number for the opcode
 */
#define NOOPARG  (-1)

/*
 * Test whether an opcode uses a ModR/M byte
 */
#define x86UsesModRM(x)   ( ((x)->digit >= 0) && ((x)->digit <= 7) )

/*
 * Test whether an opcode is defined with +rb/+rw/+rd/+i
 */
#define x86UsesRegFPU(x)  ( ((x)->digit == REGCODE) || ((x)->digit == FPUCODE) )

#endif /* INCLUDED_common_x86_h */
