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
 * $Id: operands-x86.h,v 1.1.1.1 2004/04/26 00:40:23 pa33 Exp $
 */

#ifndef INCLUDED_operands_x86_h
#define INCLUDED_operands_x86_h

/*
 * Size/attributes of the operands
 */

#define BITS8        (1 << 0)
#define BITS16       (1 << 1)
#define BITS32       (1 << 2)
#define BITS48       (1 << 3)  /* ptr16:32 or m16:32 operands */
#define BITS64       (1 << 4)  /* MMX registers */
#define BITS80       (1 << 5)  /* FPU only */
#define BITS128      (1 << 6)  /* XMM registers */
#define FAR          (1 << 7)
#define NEAR         (1 << 8)
#define SHORT        (1 << 9)
#define COLON        (1 << 10) /* operand is followed by colon */
#define TO           (1 << 11)

/*
 * Type of operand: memory, register etc
 */

#define MEMORY       (1 << 12) /* memory location */
#define REGISTER     (1 << 13) /* normal register */
#define IMMEDIATE    (1 << 14) /* immediate byte value */
#define RELATIVE     (1 << 15) /* relative address */
#define REGMEM       (1 << 16) /* byte from register or memory */
#define REG_SR       (1 << 17) /* any segment register */
#define MEMOFFS      (1 << 18) /* address offset */
#define REG_FPU      (1 << 19) /* floating point stack registers */
#define REG_MMX      (1 << 20) /* 64 bit mmx register */
#define REG_XMM      (1 << 21) /* Katmai xmm register */
#define REG_CONTROL  (1 << 22) /* control register */
#define REG_DEBUG    (1 << 23) /* debug register */
#define CONSTANT     (1 << 24) /* a numerical constant */
#define SIBBYTE      (1 << 25) /* opcode requires a SIB byte */
#define SEG16        (1 << 26) /* 16 bit segment size */
#define OFF16        (1 << 27) /* 16 bit segment offset size */
#define OFF32        (1 << 28) /* 32 bit segment offset size */

#define REG8         (REGISTER | BITS8)
#define REG16        (REGISTER | BITS16)
#define REG32        (REGISTER | BITS32)

/*
 * Placed in the 'digit' field of Instructions[] if the opcode
 * is defined with a /r in the Intel instruction set reference -
 * make sure this is greater than 7, since the digits range from
 * 0 to 7. This indicates that the ModR/M byte of the instruction
 * contains both a register and r/m operand.
 */
#define REGRM        8

/*
 * Placed in the 'digit' field of Instructions[] if the opcode
 * is defined with a +rb, +rw, or +rd, meaning the opcode is
 * increased by a value from 0-7 representing a specific register.
 * See table 3.1 in the Intel instruction set reference.
 */
#define REGCODE      9

/*
 * Placed in the 'digit' field of Instructions[] if the opcode
 * is defined with a +i, meaning the opcode is increased by a value
 * from 0-7 representing a specific floating point stack register.
 */
#define FPUCODE      10

/*
 * This goes in the opinfo[] field if we are to use the
 * RM field of the ModR/M byte to get the general purpose
 * register, instead of the REG field. This occurs for the
 * 0F 20/21/22/23 family of MOV instructions. The REG field
 * is used to compute the control/debug registers, and RM
 * is used for the general purpose register. Just make sure
 * this value is greater than any of the register values R_xxx
 * so that it is not mistaken for a specific register.
 */
#define MODFIELD_RM  0x7FF0

#endif /* INCLUDED_operands_x86_h */
