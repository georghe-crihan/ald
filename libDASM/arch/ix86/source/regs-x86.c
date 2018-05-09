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
 * $Id: regs-x86.c,v 1.1.1.1 2004/04/26 00:40:09 pa33 Exp $
 */

#include <string.h>
#include <strings.h>

#include "regs-x86.h"
#include "operands-x86.h"

/*
 * Top-level includes
 */

#include "libDASM.h"

/*
 * List of all intel registers: their indexing corresponds to
 * the R_xx values.
 */

const struct x86RegInfoDASM x86RegistersDASM[] = {
  { "ah", REGISTER | BITS8 },
  { "al", REGISTER | BITS8 },
  { "ax", REGISTER | BITS16 },
  { "bh", REGISTER | BITS8 },
  { "bl", REGISTER | BITS8 },
  { "bp", REGISTER | BITS16 },
  { "bx", REGISTER | BITS16 },
  { "ch", REGISTER | BITS8 },
  { "cl", REGISTER | BITS8 },
  { "cr0", REGISTER },
  { "cr1", REGISTER },
  { "cr2", REGISTER },
  { "cr3", REGISTER },
  { "cr4", REGISTER },
  { "cr5", REGISTER },
  { "cr6", REGISTER },
  { "cr7", REGISTER },
  { "cs", REGISTER | BITS16 },
  { "cx", REGISTER | BITS16 },
  { "dh", REGISTER | BITS8 },
  { "di", REGISTER | BITS16 },
  { "dl", REGISTER | BITS8 },
  { "dr0", REGISTER },
  { "dr1", REGISTER },
  { "dr2", REGISTER },
  { "dr3", REGISTER },
  { "dr4", REGISTER },
  { "dr5", REGISTER },
  { "dr6", REGISTER },
  { "dr7", REGISTER },
  { "ds", REGISTER | BITS16 },
  { "dx", REGISTER | BITS16 },
  { "eax", REGISTER | BITS32 },
  { "ebp", REGISTER | BITS32 },
  { "ebx", REGISTER | BITS32 },
  { "ecx", REGISTER | BITS32 },
  { "edi", REGISTER | BITS32 },
  { "edx", REGISTER | BITS32 },
  { "es", REGISTER | BITS16 },
  { "esi", REGISTER | BITS32 },
  { "esp", REGISTER | BITS32 },
  { "fs", REGISTER | BITS16 },
  { "gs", REGISTER | BITS16 },
  { "mm0", REGISTER | REG_MMX },
  { "mm1", REGISTER | REG_MMX },
  { "mm2", REGISTER | REG_MMX },
  { "mm3", REGISTER | REG_MMX },
  { "mm4", REGISTER | REG_MMX },
  { "mm5", REGISTER | REG_MMX },
  { "mm6", REGISTER | REG_MMX },
  { "mm7", REGISTER | REG_MMX },
  { "si", REGISTER | BITS16 },
  { "sp", REGISTER | BITS16 },
  { "ss", REGISTER | BITS16 },
  { "st(0)", REGISTER | REG_FPU },
  { "st(1)", REGISTER | REG_FPU },
  { "st(2)", REGISTER | REG_FPU },
  { "st(3)", REGISTER | REG_FPU },
  { "st(4)", REGISTER | REG_FPU },
  { "st(5)", REGISTER | REG_FPU },
  { "st(6)", REGISTER | REG_FPU },
  { "st(7)", REGISTER | REG_FPU },
  { "tr3", REGISTER },
  { "tr4", REGISTER },
  { "tr5", REGISTER },
  { "tr6", REGISTER },
  { "tr7", REGISTER },
  { "xmm0", REGISTER | REG_XMM },
  { "xmm1", REGISTER | REG_XMM },
  { "xmm2", REGISTER | REG_XMM },
  { "xmm3", REGISTER | REG_XMM },
  { "xmm4", REGISTER | REG_XMM },
  { "xmm5", REGISTER | REG_XMM },
  { "xmm6", REGISTER | REG_XMM },
  { "xmm7", REGISTER | REG_XMM }
};

/*
x86findRegisterDASM()
  Find register by name

Inputs: name - register name

Return: if found, index into x86RegistersDASM[]
        if not found, -1
*/

int
x86findRegisterDASM(char *name)

{
  int ii;

  for (ii = 0; ii < NUM_ELEMENTS(x86RegistersDASM); ++ii)
  {
    if (!strcasecmp(name, x86RegistersDASM[ii].name))
      return (ii);
  }

  return (-1);
} /* x86findRegisterDASM() */
