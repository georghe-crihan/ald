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
 * $Id: disasm-x86.h,v 1.2 2004/08/31 02:24:50 pa33 Exp $
 */

#ifndef INCLUDED_disasm_x86_h
#define INCLUDED_disasm_x86_h

#ifndef INCLUDED_libDASM_h
#include "libDASM.h"          /* struct disasmWorkspace */
#define INCLUDED_libDASM_h
#endif

#define   MAXBUF     32

#ifndef INCLUDED_modsib_x86_h
#include "modsib-x86.h"           /* struct x86ModAddrInfo */
#define INCLUDED_modsib_x86_h
#endif

/*
 * This struct contains information on possible opcode
 * matches - used by x86findOpCode
 */
struct x86matchInfo
{
  long bytesMatched;        /* number of bytes matched */
  struct x86OpCode *opPtr;  /* pointer to opcode data */
  int regcode;              /* register code (+rb/+rw/+rd instructions) */
  int fpucode;              /* fpu code (+i instructions) */

  int prefixPriority;       /* prefix priority */

  /*
   * ModR/M, SIB stuff
   */
  struct x86ModSibInfo msinfo;

  struct x86ModAddrInfo *modptr;

  unsigned char mod;        /* MOD portion of ModR/M byte */
  unsigned char reg;        /* REG portion of ModR/M byte */
  unsigned char rm;         /* R/M portion of ModR/M byte */

  struct x86ModAddrInfo *sibptr;

  unsigned char sib;
  unsigned char scale;
  unsigned char index;
  unsigned char base;
};

/*
 * Prototypes
 */

long x86procDisasm(struct disasmWorkspace *ws, unsigned char *data,
                   char *outbuf, unsigned int address);

#endif /* INCLUDED_disasm_x86_h */
