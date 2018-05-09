/*
 * Assembly Language Debugger
 *
 * Copyright (C) 2000 Patrick Alken
 * This program comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: set.h,v 1.1.1.1 2004/04/26 00:41:11 pa33 Exp $
 */

#ifndef INCLUDED_set_h
#define INCLUDED_set_h

#ifndef INCLUDED_main_h
#include "main.h"
#define INCLUDED_main_h
#endif

#define SET_DISPLAY_REGS       (1 << 0)
#define SET_DISPLAY_FP_REGS    (1 << 1)
#define SET_DISPLAY_MMX_REGS   (1 << 2)
#define SET_DISASM_SHOW_SYMS   (1 << 3)

#define SetStepDisplayRegs(x)       ((x)->settings |= SET_DISPLAY_REGS)
#define SetStepDisplayFpRegs(x)     ((x)->settings |= SET_DISPLAY_FP_REGS)
#define SetStepDisplayMmxRegs(x)    ((x)->settings |= SET_DISPLAY_MMX_REGS)
#define SetDisasmShowSyms(x)        ((x)->settings |= SET_DISASM_SHOW_SYMS)

#define IsSetStepDisplayRegs(x)     ((x)->settings & SET_DISPLAY_REGS)
#define IsSetStepDisplayFpRegs(x)   ((x)->settings & SET_DISPLAY_FP_REGS)
#define IsSetStepDisplayMmxRegs(x)  ((x)->settings & SET_DISPLAY_MMX_REGS)
#define IsSetDisasmShowSyms(x)      ((x)->settings & SET_DISASM_SHOW_SYMS)

#define UnsetStepDisplayRegs(x)     ((x)->settings &= ~SET_DISPLAY_REGS)
#define UnsetStepDisplayFpRegs(x)   ((x)->settings &= ~SET_DISPLAY_FP_REGS)
#define UnsetStepDisplayMmxRegs(x)  ((x)->settings &= ~SET_DISPLAY_MMX_REGS)
#define UnsetDisasmShowSyms(x)      ((x)->settings &= ~SET_DISASM_SHOW_SYMS)

/*
 * These SETSYN_xxx are indices into the array setCmdsSyntax[]
 */
enum
{
  SETSYN_ARGS,
  SETSYN_DISASM_SHOW_SYMS,
  SETSYN_ENTRY,
  SETSYN_OFFSET,
  SETSYN_OUTPUT,
  SETSYN_PAUSEPRINT,
  SETSYN_PROMPT,
  SETSYN_STEP_DISP_REGS,
  SETSYN_STEP_DISP_FPREGS,
  SETSYN_STEP_DISP_MMXREGS
};

/*
 * Prototypes
 */

void DisplaySettings(struct aldWorkspace *ws);
struct Command *FindSetCommand(char *name, unsigned int *flags);

#endif /* INCLUDED_set_h */
