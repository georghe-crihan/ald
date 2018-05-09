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
 * $Id: args-x86.h,v 1.2 2004/08/31 02:24:50 pa33 Exp $
 */

#ifndef INCLUDED_args_x86_h
#define INCLUDED_args_x86_h

#ifndef INCLUDED_libDASM_h
#include "libDASM.h"           /* struct disasmWorkspace */
#define INCLUDED_libDASM_h
#endif

#ifndef INCLUDED_disasm_x86_h
#include "disasm-x86.h"        /* struct x86matchInfo */
#define INCLUDED_disasm_x86_h
#endif

/*
 * Prototypes
 */

int x86constructArguments(struct disasmWorkspace *ws,
                          unsigned char **data,
                          struct x86matchInfo *ptr, char *outbuf,
                          unsigned int address);

#endif /* INCLUDED_args_x86_h */
