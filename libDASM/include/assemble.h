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
 * $Id: assemble.h,v 1.2 2004/10/09 17:41:50 pa33 Exp $
 */

#ifndef INCLUDED_libDASM_assemble_h
#define INCLUDED_libDASM_assemble_h

#ifndef INCLUDED_libDASM_h
#include "libDASM.h"
#define INCLUDED_libDASM_h
#endif

#ifndef INCLUDED_api_cfgDASM_h
#include "api_cfgDASM.h"           /* INTEL86 */
#define INCLUDED_api_cfgDASM_h
#endif

struct asmWorkspace
{
  unsigned int flags;            /* DA_xxx */
};

struct immediateInfo
{
  long inum;                     /* integer value */
  unsigned int flags;            /* DASM_IMMED_xxx */
};

#define DASM_IMMED_BITS8         (1 << 0)
#define DASM_IMMED_BITS16        (1 << 1)
#define DASM_IMMED_BITS32        (1 << 2)

#ifndef INCLUDED_asm_x86_h
#include "../arch/ix86/include/asm-x86.h"
#define INCLUDED_asm_x86_h
#endif

/*
 * Prototypes
 */

struct asmWorkspace *initAsm(unsigned int flags);
void termAsm(struct asmWorkspace *ws);
void flagsAsm(struct asmWorkspace *ws, unsigned int flags);
int procAsm(struct asmWorkspace *ws, char *str,
            unsigned char *outbuf);

#endif /* INCLUDED_libDASM_assemble_h */
