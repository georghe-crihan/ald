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
 * $Id: regs-x86.h,v 1.1.1.1 2004/04/26 00:40:23 pa33 Exp $
 */

#ifndef INCLUDED_regs_x86_h
#define INCLUDED_regs_x86_h

struct x86RegInfoDASM
{
  char *name;         /* register name */
  unsigned int flags; /* register flags */
};

/*
 * Register indexes into x86RegistersDASM[]
 */
enum
{
  R_AH,
  R_AL,
  R_AX,
  R_BH,
  R_BL,
  R_BP,
  R_BX,
  R_CH,
  R_CL,
  R_CR0,
  R_CR1,
  R_CR2,
  R_CR3,
  R_CR4,
  R_CR5,
  R_CR6,
  R_CR7,
  R_CS,
  R_CX,
  R_DH,
  R_DI,
  R_DL,
  R_DR0,
  R_DR1,
  R_DR2,
  R_DR3,
  R_DR4,
  R_DR5,
  R_DR6,
  R_DR7,
  R_DS,
  R_DX,
  R_EAX,
  R_EBP,
  R_EBX,
  R_ECX,
  R_EDI,
  R_EDX,
  R_ES,
  R_ESI,
  R_ESP,
  R_FS,
  R_GS,
  R_MM0,
  R_MM1,
  R_MM2,
  R_MM3,
  R_MM4,
  R_MM5,
  R_MM6,
  R_MM7,
  R_SI,
  R_SP,
  R_SS,
  R_ST0,
  R_ST1,
  R_ST2,
  R_ST3,
  R_ST4,
  R_ST5,
  R_ST6,
  R_ST7,
  R_TR3,
  R_TR4,
  R_TR5,
  R_TR6,
  R_TR7,
  R_XMM0,
  R_XMM1,
  R_XMM2,
  R_XMM3,
  R_XMM4,
  R_XMM5,
  R_XMM6,
  R_XMM7
};

/*
 * Prototypes
 */

int x86findRegisterDASM(char *name);

/*
 * External declarations
 */

extern const struct x86RegInfoDASM x86RegistersDASM[];

#endif /* INCLUDED_regs_x86_h */
