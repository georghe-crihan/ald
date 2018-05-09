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
 * $Id: libDASM.h,v 1.3 2004/10/09 17:41:50 pa33 Exp $
 */

#ifndef INCLUDED_libDASM_libDASM_h
#define INCLUDED_libDASM_libDASM_h

#ifndef INCLUDED_api_cfgDASM_h
#include "api_cfgDASM.h"           /* INTEL86 */
#define INCLUDED_api_cfgDASM_h
#endif

#ifndef INCLUDED_libDASM_version_h
#include "version.h"
#define INCLUDED_libDASM_version_h
#endif

/*
 * MAX_OPCODE_LEN should be set to the maximum number of bytes in
 * one opcode on your architecture.
 */

#ifdef INTEL86

/*
 * Intel's max opcode length is actually 17 bytes I believe, but
 * rounding up cannot hurt.
 */

# define MAX_OPCODE_LEN  20

#else

# error "Please manually set MAX_OPCODE_LEN in libDASM/include/libDASM.h"

#endif

#define MAXLINE          1024

/*
 * General flags
 */

#define DA_16BITMODE     (1 << 0)  /* we are in 16 bit mode */
#define DA_32BITMODE     (1 << 1)  /* we are in 32 bit mode */

/*
 * Prefix flags
 */
#define PX_LOCK          (1 << 0)   /* lock */
#define PX_REPNE         (1 << 1)   /* repne */
#define PX_REP           (1 << 2)   /* rep */
#define PX_REPE          (1 << 3)   /* repe */
#define PX_SEGOVER       (1 << 4)   /* segment override */
#define PX_OPOVER        (1 << 5)   /* operand size override (0x66) */
#define PX_ADDROVER      (1 << 6)   /* address size override (0x67) */

/*
 * Include various prototypes
 */

#ifndef INCLUDED_libDASM_assemble_h
#include "assemble.h"               /* struct asmWorkspace */
#define INCLUDED_libDASM_assemble_h
#endif

#ifndef INCLUDED_libDASM_disassemble_h
#include "disassemble.h"            /* struct disasmWorkspace */
#define INCLUDED_libDASM_disassemble_h
#endif

/*
 * Main library workspace
 */
struct dasmWorkspace
{
  struct asmWorkspace *asmWorkspace_p;
  struct disasmWorkspace *disasmWorkspace_p;
};

/*
 * Number of elements in an array
 */
#define NUM_ELEMENTS(x) ((int) (sizeof((x)) / sizeof(*(x))))

/*
 * Prototypes
 */

struct dasmWorkspace *initDASM(unsigned int flags);
void termDASM(struct dasmWorkspace *ws);
int assembleDASM(struct dasmWorkspace *ws, char *str,
                 unsigned char *outbuf);
long disassembleDASM(struct dasmWorkspace *ws, unsigned char *data,
                     char *outbuf, unsigned int address);

#endif /* INCLUDED_libDASM_libDASM_h */
