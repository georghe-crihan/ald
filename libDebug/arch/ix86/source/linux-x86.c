/*
 * libDebug
 *
 * Copyright (C) 2000 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: linux-x86.c,v 1.1.1.1 2004/04/26 00:41:01 pa33 Exp $
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <assert.h>
#include <string.h>
#include <signal.h>

/*
 * Top-level includes
 */
#include "args.h"
#include "break.h"
#include "libDebug.h"

/*
 * libString includes
 */
#include "alloc.h"
#include "Strn.h"

/*
 * OS specific junk
 */
/*#include <asm/elf.h>*/

/*static elf_fpxregset_t fpxData;*/

/*
x86initRegistersDebug()
  Initialize the valptr field of x86Registers[] to point to the
corresponding entry in ws->regContents

Return: 1 if successful
        0 if not
*/

int
x86initRegistersDebug(struct debugWorkspace *ws)

{
  int ii; /* looping */

  /*
   * Set up pointers to general registers
   */

  x86Registers[REG_EAX].valptr = (void *) &(ws->regContents.Regs.regs.eax);
  x86Registers[REG_EBX].valptr = (void *) &(ws->regContents.Regs.regs.ebx);
  x86Registers[REG_ECX].valptr = (void *) &(ws->regContents.Regs.regs.ecx);
  x86Registers[REG_EDX].valptr = (void *) &(ws->regContents.Regs.regs.edx);
  x86Registers[REG_ESP].valptr = (void *) &(ws->regContents.Regs.regs.esp);
  x86Registers[REG_EBP].valptr = (void *) &(ws->regContents.Regs.regs.ebp);
  x86Registers[REG_ESI].valptr = (void *) &(ws->regContents.Regs.regs.esi);
  x86Registers[REG_EDI].valptr = (void *) &(ws->regContents.Regs.regs.edi);
  x86Registers[REG_DS].valptr = (void *) &(ws->regContents.Regs.regs.xds);
  x86Registers[REG_ES].valptr = (void *) &(ws->regContents.Regs.regs.xes);
  x86Registers[REG_FS].valptr = (void *) &(ws->regContents.Regs.regs.xfs);
  x86Registers[REG_GS].valptr = (void *) &(ws->regContents.Regs.regs.xgs);
  x86Registers[REG_SS].valptr = (void *) &(ws->regContents.Regs.regs.xss);
  x86Registers[REG_CS].valptr = (void *) &(ws->regContents.Regs.regs.xcs);
  x86Registers[REG_EIP].valptr = (void *) &(ws->regContents.Regs.regs.eip);
  x86Registers[REG_EFLAGS].valptr = (void *) &(ws->regContents.Regs.regs.eflags);

  x86Registers[REG_AH].valptr = (void *) &(ws->regContents.Regs.regs.eax);
  x86Registers[REG_AL].valptr = (void *) &(ws->regContents.Regs.regs.eax);
  x86Registers[REG_AX].valptr = (void *) &(ws->regContents.Regs.regs.eax);

  x86Registers[REG_BH].valptr = (void *) &(ws->regContents.Regs.regs.ebx);
  x86Registers[REG_BL].valptr = (void *) &(ws->regContents.Regs.regs.ebx);
  x86Registers[REG_BX].valptr = (void *) &(ws->regContents.Regs.regs.ebx);

  x86Registers[REG_CH].valptr = (void *) &(ws->regContents.Regs.regs.ecx);
  x86Registers[REG_CL].valptr = (void *) &(ws->regContents.Regs.regs.ecx);
  x86Registers[REG_CX].valptr = (void *) &(ws->regContents.Regs.regs.ecx);

  x86Registers[REG_DH].valptr = (void *) &(ws->regContents.Regs.regs.edx);
  x86Registers[REG_DL].valptr = (void *) &(ws->regContents.Regs.regs.edx);
  x86Registers[REG_DX].valptr = (void *) &(ws->regContents.Regs.regs.edx);

  x86Registers[REG_SP].valptr = (void *) &(ws->regContents.Regs.regs.esp);
  x86Registers[REG_BP].valptr = (void *) &(ws->regContents.Regs.regs.ebp);
  x86Registers[REG_SI].valptr = (void *) &(ws->regContents.Regs.regs.esi);
  x86Registers[REG_DI].valptr = (void *) &(ws->regContents.Regs.regs.edi);

  x86Registers[REG_IP].valptr = (void *) &(ws->regContents.Regs.regs.eip);
  x86Registers[REG_FLAGS].valptr = (void *) &(ws->regContents.Regs.regs.eflags);

  /*
   * Floating point unit data registers
   */

  for (ii = 0; ii < FPU_NUM_DATA_REGS; ++ii)
  {
    x86Registers[REG_ST0 + ii].valptr =
      (void *) ((unsigned char *) ws->regContents.Regs.i387.st_space +
                ii * FPU_DATA_REG_SIZE);
  }

  /*
   * Other floating point unit registers
   */
  x86Registers[REG_FCTRL].valptr = (void *) &(ws->regContents.Regs.i387.cwd);
  x86Registers[REG_FSTAT].valptr = (void *) &(ws->regContents.Regs.i387.swd);
  x86Registers[REG_FTAG].valptr = (void *) &(ws->regContents.Regs.i387.twd);
  x86Registers[REG_FIP].valptr = (void *) &(ws->regContents.Regs.i387.fip);
  x86Registers[REG_FCS].valptr = (void *) &(ws->regContents.Regs.i387.fcs);
  x86Registers[REG_FOPCODE].valptr = (void *) ((char *) x86Registers[REG_FCS].valptr + sizeof(unsigned short));
  x86Registers[REG_FOOFF].valptr = (void *) &(ws->regContents.Regs.i387.foo);
  x86Registers[REG_FOSEG].valptr = (void *) &(ws->regContents.Regs.i387.fos);

  /*
   * MMX registers
   */

  for (ii = 0; ii < MMX_NUM_REGS; ++ii)
  {
    /*
     * The mmN register is the low 64 bits of the stN register
     * XXX - this is little endian specific
     */
    x86Registers[REG_MM0 + ii].valptr =
      (void *) ((unsigned char *) ws->regContents.Regs.i387.st_space +
                ii * FPU_DATA_REG_SIZE);
  }

  return (1);
} /* x86initRegistersDebug() */

/*
x86getCurrentInstruction()
  Determine the address of the next instruction to be executed (eip)
and return it.

Return: address of next instruction

Side effects: if the ptrace() call fails, err is set to 1
*/

unsigned long
x86getCurrentInstruction(struct debugWorkspace *ws, int *err)

{
  assert(ws->pid != NOPID);

  /*
   * Make sure not to use a temporary variable here, or the breakpoint code in
   * x86Continue() will overwrite new register contents with old ones when it calls
   * x86SetCurrentInstruction()
   */
  if (ptrace(PT_GETREGS, ws->pid, 0, &(ws->regContents.Regs.regs)) != 0)
    *err = 1;

  return ((unsigned long) ws->regContents.Regs.regs.eip);
} /* x86getCurrentInstruction() */

/*
x86setCurrentInstruction()
  Set eip to the given address

Return: 1 if successful
        0 if not
*/

int
x86setCurrentInstruction(struct debugWorkspace *ws, unsigned long address)

{
  assert(ws->pid != NOPID);

  ws->regContents.Regs.regs.eip = address;

  if (ptrace(PT_SETREGS, ws->pid, 0, &(ws->regContents.Regs.regs)) != 0)
    return (0);

  /*
   * Keep our instruction pointer updated
   */
  ws->instructionPointer = address;

  return (1);
} /* x86setCurrentInstruction() */

/*
x86getRegistersDebug()
  Update our local copy of the debugged process' registers

Inputs: ws - debug workspace

Return: 1 if successful
        0 upon ptrace error
*/

int
x86getRegistersDebug(struct debugWorkspace *ws)

{
  if (ptrace(PT_GETREGS, ws->pid, 0, &(ws->regContents.Regs.regs)) != 0)
    return (0); /* something went wrong */

#if 1

  if (ptrace(PT_GETFPREGS, ws->pid, 0, &(ws->regContents.Regs.i387)) != 0)
    return (0); /* something went wrong */

#else

  if (ptrace(PT_GETFPXREGS, ws->pid, 0, &fpxData)) != 0)
    return (0); /* something went wrong */

#endif

  /*
   * Save the location of our next instruction
   */
  ws->instructionPointer = ws->regContents.Regs.regs.eip;

  return (1);
} /* x86getRegistersDebug() */

/*
x86readFPUDebug()
  Put the contents of the fpu into a given structure

Inputs: ws       - debug workspace
        fpuState - modified to contain state of fpu

Return: 1 if successful
*/

int
x86readFPUDebug(struct debugWorkspace *ws, struct x86fpuInfo *fpuState)

{
  long fcs;

  /* control register */
  fpuState->fctrl =
    (unsigned short) *((long *) x86Registers[REG_FCTRL].valptr);

  /* status register */
  fpuState->fstat =
    (unsigned short) *((long *) x86Registers[REG_FSTAT].valptr);

  /* tag register */
  fpuState->ftag =
    (unsigned short) *((long *) x86Registers[REG_FTAG].valptr);

  /* last instruction pointer (offset) */
  fpuState->fip = (long) *((long *) x86Registers[REG_FIP].valptr);

  fcs = (long) *((long *) x86Registers[REG_FCS].valptr);

  /* last instruction pointer (segment) */
  /*fpuState->fcs = (unsigned short) (fcs >> 16);*/
  fpuState->fcs = (unsigned short) (fcs & 0xFFFF);

  /* opcode */
  /*fpuState->fopcode = (unsigned short) (fcs & 0xFFFF);*/
  fpuState->fopcode = (unsigned short) (fcs >> 16);

  /* last data operand pointer (offset) */
  fpuState->fooff = (long) *((long *) x86Registers[REG_FOOFF].valptr);

  /* last data operand pointer (segment) */
  fpuState->foseg = (long) *((long *) x86Registers[REG_FOSEG].valptr);

  memcpy(fpuState->stptr,
         (unsigned char *) ws->regContents.Regs.i387.st_space,
         FPU_NUM_DATA_REGS * FPU_DATA_REG_SIZE);

  return (1);
} /* x86readFPUDebug() */

/*
x86writeRegisterDebug()
  Update our local copy of the register with the given value and call ptrace
to write the changes to the process' registers

Inputs: ws     - debug workspace
        rptr   - pointer to register in x86Registers[]
        regVal - contains new value for register

Return: 1 if successful
        0 upon ptrace error
*/

int
x86writeRegisterDebug(struct debugWorkspace *ws, struct x86RegInfo *rptr,
                      struct x86RegValue *regVal)

{
  if ((rptr->flags & R_GENERAL) ||
      ((rptr->flags & R_FPU) && !(rptr->flags & R_FPU_DATA)))
  {
    /*
     * update ws->regContents.Regs with the new value of type long
     */
    *((unsigned long *) rptr->valptr) = regVal->lvalue;
  }
  else if (rptr->flags & R_FPU_DATA)
  {
    /*
     * update the appropriate register location with the new value of the fpu
     * data register
     */
    memcpy((unsigned char *)rptr->valptr, regVal->stptr, FPU_DATA_REG_SIZE);
  }

  /*
   * Call ptrace to set the actual register
   */
  if (ptrace(PT_SETREGS, ws->pid, 0, &(ws->regContents.Regs.regs)) != 0)
    return (0); /* error */

  if (ptrace(PT_SETFPREGS, ws->pid, 0, &(ws->regContents.Regs.i387)) != 0)
    return (0); /* error */

  return (1);
} /* x86writeRegistersDebug() */
