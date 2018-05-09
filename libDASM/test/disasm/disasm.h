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
 * $Id: disasm.h,v 1.1.1.1 2004/04/26 00:40:24 pa33 Exp $
 */

#ifndef INCLUDED_disasm_h
#define INCLUDED_disasm_h

#ifndef INCLUDED_libDASM_h
#include "libDASM.h"
#define INCLUDED_libDASM_h
#endif

#ifndef MAX_FILE_READ
# define MAX_FILE_READ     1
#endif

/*
 * Size of our circular buffer: *must* be a power of 2.
 * Also, this must be larger than MAX_OPCODE_LEN defined
 * below, since the current opcode to be disassembled will
 * be stored in a buffer of this size.
 */
#define CIRC_SIZE          64

/*
 * Make this bigger than any possible opcode
 */
#define MAX_OPCODE_LEN     20

struct mainWorkspace
{
  struct disasmWorkspace *disasmWorkspace_p;

  unsigned char circInput[CIRC_SIZE];
  int circIndex;            /* index into circInput[] */

  int bytesNeeded;          /* number of opcode bytes needed */

  unsigned int offset;      /* file offset */
};

/*
 * Prototypes
 */

struct mainWorkspace *initMain(unsigned int flags);
void termMain(struct mainWorkspace *ws);
int procMain(struct mainWorkspace *ws, unsigned char *buffer, int len);
int flushMain(struct mainWorkspace *ws);

#endif /* INCLUDED_disasm_h */
