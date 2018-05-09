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
 * $Id: prefix-x86.h,v 1.1.1.1 2004/04/26 00:40:23 pa33 Exp $
 */

#ifndef INCLUDED_prefix_x86_h
#define INCLUDED_prefix_x86_h

#ifndef INCLUDED_libDASM_h
#include "libDASM.h"           /* struct disasmWorkspace */
#define INCLUDED_libDASM_h
#endif

#ifndef INCLUDED_disasm_x86_h
#include "disasm-x86.h"        /* struct x86OpCode */
#define INCLUDED_disasm_x86_h
#endif

/*
 * Prototypes
 */

unsigned char x86processPrefix(struct disasmWorkspace *ws, unsigned char *data);
int x86testPrefix(struct disasmWorkspace *ws, struct x86OpCode *ptr);
unsigned int x86addrSizeAttribute(struct disasmWorkspace *ws);

#endif /* INCLUDED_prefix_x86_h */
