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
 * $Id: asm-x86.h,v 1.1.1.1 2004/04/26 00:40:23 pa33 Exp $
 */

#ifndef INCLUDED_asm_x86_h
#define INCLUDED_asm_x86_h

#ifndef INCLUDED_libDASM_assemble_h
#include "assemble.h"           /* struct asmWorkspace */
#define INCLUDED_libDASM_assemble_h
#endif

struct instructionInfo
{
  /*
   * These fields are filled in by parseInstructionAsm()
   */

  int name;                      /* index into x86InstructionNames[] */

  int opnum;                     /* number of operands */
  unsigned int operands[3];      /* operand flags */
  int opinfo[3];                 /* additional operand info */

  struct immediateInfo immInfo;  /* numerical constant information */
  int hasImmed;                  /* has an immediate operand? */

  unsigned int flags;            /* instruction flags (X86INS_xxx) */
};

/*
 * Instruction flags
 */

#define X86INS_BITS8      (1 << 0)  /* 8 bit instruction */
#define X86INS_BITS16     (1 << 1)  /* 16 bit instruction */
#define X86INS_BITS32     (1 << 2)  /* 32 bit instruction */

/*
 * Prototypes
 */

int x86procAsm(struct asmWorkspace *ws, char *str,
               unsigned char *outbuf);

#endif /* INCLUDED_asm_x86_h */
