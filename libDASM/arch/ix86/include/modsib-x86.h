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
 * $Id: modsib-x86.h,v 1.1.1.1 2004/04/26 00:40:23 pa33 Exp $
 */

#ifndef INCLUDED_modsib_x86_h
#define INCLUDED_modsib_x86_h

struct x86ModAddrInfo
{
  int index;           /* index into x86ModAddresses[] (M_xxx) */
  unsigned int flags;  /* MF_xxx */
};

/* flags */
#define MF_DISP8        (1 << 0)  /* 8 bit displacement follows Mod/Sib bytes */
#define MF_DISP16       (1 << 1)  /* 16 bit displacement follows Mod/Sib bytes */
#define MF_DISP32       (1 << 2)  /* 32 bit displacement follows Mod/Sib bytes */
#define MF_SIB          (1 << 3)  /* SIB byte follows ModR/M byte */
#define MF_REGISTER     (1 << 4)  /* r/m field specifies a register, not a memory offset */

#define MAX_MOD         4         /* number of values mod field can take */
#define MAX_REG         8         /* number of values reg field can take */
#define MAX_RM          8         /* number of values r/m field can take */

struct x86ModSibInfo
{
  struct x86ModAddrInfo *modptr;
  struct x86ModAddrInfo *sibptr;

  /*
   * ModR/M byte information
   */
  unsigned char modrm;
  unsigned char mod;
  unsigned char reg;
  unsigned char rm;

  /*
   * SIB byte information
   */
  unsigned char sib;
  unsigned char scale;
  unsigned char index;
  unsigned char base;

  /*
   * Displacement, if any
   */
  unsigned int disp;
};

enum
{
  M_AH,
  M_AL,
  M_AX,
  M_BH,
  M_BL,
  M_BP,
  M_BX,
  M_BP_DI,
  M_BP_SI,
  M_BX_DI,
  M_BX_SI,
  M_CH,
  M_CL,
  M_CX,
  M_DH,
  M_DI,
  M_DL,
  M_DX,
  M_EAX,
  M_EBP,
  M_EBX,
  M_ECX,
  M_EDI,
  M_EDX,
  M_ESI,
  M_ESP,
  M_MM0,
  M_MM1,
  M_MM2,
  M_MM3,
  M_MM4,
  M_MM5,
  M_MM6,
  M_MM7,
  M_SI,
  M_SP,
  M_XMM0,
  M_XMM1,
  M_XMM2,
  M_XMM3,
  M_XMM4,
  M_XMM5,
  M_XMM6,
  M_XMM7,
  M_NONE
};

#ifndef INCLUDED_libDASM_h
#include "libDASM.h"         /* struct disasmWorkspace */
#define INCLUDED_libDASM_h
#endif

#ifndef INCLUDED_common_x86_h
#include "common-x86.h"        /* struct x86OpCode */
#define INCLUDED_common_x86_h
#endif

/*
 * Prototypes
 */

int x86processModSib(struct disasmWorkspace *ws, unsigned char *data,
                     struct x86OpCode *ptr, struct x86ModSibInfo *msinfo);
char *x86getModAddrStr(int index);
char *x86getModRegister(unsigned char index, unsigned int flags);
char *x86getSibBaseRegister(unsigned char base);

#endif /* INCLUDED_modsib_x86_h */
