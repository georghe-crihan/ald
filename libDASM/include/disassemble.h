/*
 * libDASM
 *
 * Copyright (C) 2000-2003 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: disassemble.h,v 1.4 2004/10/09 17:41:50 pa33 Exp $
 */

#ifndef INCLUDED_libDASM_disassemble_h
#define INCLUDED_libDASM_disassemble_h

#ifndef INCLUDED_libDASM_h
#include "libDASM.h"
#define INCLUDED_libDASM_h
#endif

#ifndef INCLUDED_api_cfgDASM_h
#include "api_cfgDASM.h"             /* INTEL86 */
#define INCLUDED_api_cfgDASM_h
#endif

struct disasmWorkspace
{
  unsigned int flags;            /* DA_xxx */

  unsigned int prefixFlags;      /* PX_xxx */
  int segmentOverride;           /* segment override register, if any */

  /*
   * For relative operands, store the exact target address here,
   * so that the calling program can look up symbols/functions
   * corresponding to the relative address. This variable will
   * always be 0 when returning from a disassembly call unless
   * there was a relative operand.
   */
  unsigned int effectiveAddress;
};

/*
 * These guys need struct disasmWorkspace so include them after
 * the definition
 */

#ifdef INTEL86

#ifndef INCLUDED_disasm_x86_h
#include "../arch/ix86/include/disasm-x86.h"
#define INCLUDED_disasm_x86_h
#endif

#endif /* INTEL86 */

/*
 * Prototypes
 */
struct disasmWorkspace *initDisasm(unsigned int flags);
void termDisasm(struct disasmWorkspace *ws);
void flagsDisasm(struct disasmWorkspace *ws, unsigned int flags);
long procDisasm(struct disasmWorkspace *ws, unsigned char *data,
                char *outbuf, unsigned int address);

#endif /* INCLUDED_libDASM_disassemble_h */
