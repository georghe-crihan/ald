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
 * $Id: openbsd-x86.c,v 1.1.1.1 2004/04/26 00:41:00 pa33 Exp $
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <assert.h>
#include <string.h>
#include <signal.h>
#include <machine/reg.h>
#include <machine/npx.h>

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
 * Local: structure which will contain register info
 */
/*static struct reg Regs;*/

/*
x86initRegistersDebug()
  Initialize the valptr field of x86Registers[] to point to the corresponding
entry in ws->regContents

Return: 1 if successful
        0 if not
*/

int
x86initRegistersDebug(struct debugWorkspace *ws)

{
  int ii;       /* looping */
  int fdataoff; /* offset to fpu data registers */

  /*
   * Set up pointers to general registers
   */

  x86Registers[REG_EAX].valptr = (void *) &(ws->regContents.Regs.r_eax);
  x86Registers[REG_EBX].valptr = (void *) &(ws->regContents.Regs.r_ebx);
  x86Registers[REG_ECX].valptr = (void *) &(ws->regContents.Regs.r_ecx);
  x86Registers[REG_EDX].valptr = (void *) &(ws->regContents.Regs.r_edx);
  x86Registers[REG_ESP].valptr = (void *) &(ws->regContents.Regs.r_esp);
  x86Registers[REG_EBP].valptr = (void *) &(ws->regContents.Regs.r_ebp);
  x86Registers[REG_ESI].valptr = (void *) &(ws->regContents.Regs.r_esi);
  x86Registers[REG_EDI].valptr = (void *) &(ws->regContents.Regs.r_edi);
  x86Registers[REG_DS].valptr = (void *) &(ws->regContents.Regs.r_ds);
  x86Registers[REG_ES].valptr = (void *) &(ws->regContents.Regs.r_es);
  x86Registers[REG_FS].valptr = (void *) &(ws->regContents.Regs.r_fs);
  x86Registers[REG_GS].valptr = (void *) &(ws->regContents.Regs.r_gs);
  x86Registers[REG_SS].valptr = (void *) &(ws->regContents.Regs.r_ss);
  x86Registers[REG_CS].valptr = (void *) &(ws->regContents.Regs.r_cs);
  x86Registers[REG_EIP].valptr = (void *) &(ws->regContents.Regs.r_eip);
  x86Registers[REG_EFLAGS].valptr = (void *) &(ws->regContents.Regs.r_eflags);

  x86Registers[REG_AH].valptr = (void *) &(ws->regContents.Regs.r_eax);
  x86Registers[REG_AL].valptr = (void *) &(ws->regContents.Regs.r_eax);
  x86Registers[REG_AX].valptr = (void *) &(ws->regContents.Regs.r_eax);

  x86Registers[REG_BH].valptr = (void *) &(ws->regContents.Regs.r_ebx);
  x86Registers[REG_BL].valptr = (void *) &(ws->regContents.Regs.r_ebx);
  x86Registers[REG_BX].valptr = (void *) &(ws->regContents.Regs.r_ebx);

  x86Registers[REG_CH].valptr = (void *) &(ws->regContents.Regs.r_ecx);
  x86Registers[REG_CL].valptr = (void *) &(ws->regContents.Regs.r_ecx);
  x86Registers[REG_CX].valptr = (void *) &(ws->regContents.Regs.r_ecx);

  x86Registers[REG_DH].valptr = (void *) &(ws->regContents.Regs.r_edx);
  x86Registers[REG_DL].valptr = (void *) &(ws->regContents.Regs.r_edx);
  x86Registers[REG_DX].valptr = (void *) &(ws->regContents.Regs.r_edx);

  x86Registers[REG_SP].valptr = (void *) &(ws->regContents.Regs.r_esp);
  x86Registers[REG_BP].valptr = (void *) &(ws->regContents.Regs.r_ebp);
  x86Registers[REG_SI].valptr = (void *) &(ws->regContents.Regs.r_esi);
  x86Registers[REG_DI].valptr = (void *) &(ws->regContents.Regs.r_edi);

  x86Registers[REG_IP].valptr = (void *) &(ws->regContents.Regs.r_eip);
  x86Registers[REG_FLAGS].valptr = (void *) &(ws->regContents.Regs.r_eflags);

  /*
   * Floating point unit data registers
   *
   * ptrace() stores the fpu registers in a struct fpreg which consists
   * of a 108 byte array __data[] under OpenBSD. The kernel stores the
   * actual fpu registers into a struct save87 (defined in machine/npx.h)
   * and then bcopies this struct into the struct fpreg which is returned.
   *
   * See: src/sys/arch/i386/i386/process_machdep.c, function
   * process_read_fpregs().
   *
   * So the assignment of bytes in __data[] corresponds to the setup of
   * struct save87.
   */

  fdataoff = 28; /* 6 regs * 4 bytes per reg + 4 bytes of padding */
  for (ii = 0; ii < FPU_NUM_DATA_REGS; ++ii)
  {
    /*
     * The FPU data registers are 80 bits (10 bytes) and come
     * after the 6 special purpose registers
     */
    x86Registers[REG_ST0 + ii].valptr =
      (void *) &(ws->regContents.fpRegs.__data[fdataoff + ii*10]);
  }

  /*
   * Other floating point unit registers - see npx.h (struct env87)
   */
  x86Registers[REG_FCTRL].valptr = (void *) &(ws->regContents.fpRegs.__data[0]);
  x86Registers[REG_FSTAT].valptr = (void *) &(ws->regContents.fpRegs.__data[sizeof(long)]);
  x86Registers[REG_FTAG].valptr = (void *) &(ws->regContents.fpRegs.__data[2*sizeof(long)]);
  x86Registers[REG_FIP].valptr = (void *) &(ws->regContents.fpRegs.__data[3*sizeof(long)]);
  x86Registers[REG_FCS].valptr = (void *) &(ws->regContents.fpRegs.__data[4*sizeof(long)]);
  x86Registers[REG_FOOFF].valptr = (void *) &(ws->regContents.fpRegs.__data[5*sizeof(long)]);
  x86Registers[REG_FOSEG].valptr = (void *) &(ws->regContents.fpRegs.__data[6*sizeof(long)]);

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
      (void *) &(ws->regContents.fpRegs.__data[fdataoff + ii*10]);
  }

  return (1);
} /* x86initRegistersDebug() */

/*
x86getCurrentInstruction()
  Determine the address of the next instruction to be executed (eip)
and return it.

Return: address of next instruction

Side effects: 'err' is set to 1 if ptrace() fails
*/

unsigned long
x86getCurrentInstruction(struct debugWorkspace *ws, int *err)

{
  assert(ws->pid != NOPID);

  /*
   * Make sure to always use 'U' here and not a temporary variable,
   * or the breakpoint code in x86Continue() will overwrite new
   * register contents with old ones when it calls
   * x86SetCurrentInstruction()
   */
  if (ptrace(PT_GETREGS, ws->pid, (caddr_t) &(ws->regContents.Regs), 0) != 0)
    *err = 1;

  return ((unsigned long) ws->regContents.Regs.r_eip);
} /* x86getCurrentInstruction() */

/*
x86setCurrentInstruction()
  Set eip to the given address

Return: 1 if successful
        0 if not
*/

int
x86setCurrentInstruction(struct debugWorkspace *ws,
                         unsigned long address)

{
  assert(ws->pid != NOPID);

  ws->regContents.Regs.r_eip = address;

  if (ptrace(PT_SETREGS, ws->pid, (caddr_t) &(ws->regContents.Regs), 0) != 0)
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
  if (ptrace(PT_GETREGS, ws->pid, (caddr_t) &(ws->regContents.Regs), 0) != 0)
    return (0); /* something went wrong */

  if (ptrace(PT_GETFPREGS, ws->pid, (caddr_t) &(ws->regContents.fpRegs), 0) != 0)
    return (0); /* something went wrong */

  /*
   * Save the location of our next instruction
   */
  ws->instructionPointer = ws->regContents.Regs.r_eip;

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
  struct save87 *fpframe;

  /*
   * Refer to machine/reg.h and machine/npx.h for these
   */

  fpframe = (struct save87 *) &(ws->regContents.fpRegs);

  fpuState->fctrl = fpframe->sv_env.en_cw;
  fpuState->fstat = fpframe->sv_env.en_sw;
  fpuState->ftag = fpframe->sv_env.en_tw;
  fpuState->fip = fpframe->sv_env.en_fip;
  fpuState->fcs = fpframe->sv_env.en_fcs;
  fpuState->fopcode = fpframe->sv_env.en_opcode;
  fpuState->fooff = fpframe->sv_env.en_foo;
  fpuState->foseg = fpframe->sv_env.en_fos;

  memcpy(fpuState->stptr,
         fpframe->sv_ac,
         FPU_NUM_DATA_REGS * FPU_DATA_REG_SIZE);

#if 0
  fpuState->fctrl = *((unsigned short *) x86Registers[REG_FCTRL].valptr);
  fpuState->fstat = *((unsigned short *) x86Registers[REG_FSTAT].valptr);
  fpuState->ftag = *((unsigned short *) x86Registers[REG_FTAG].valptr);
  fpuState->fip = *((long *) x86Registers[REG_FIP].valptr);
  fpuState->fcs = (unsigned short) (*((unsigned long *) x86Registers[REG_FCS].valptr) >> 16);
  fpuState->fopcode = (unsigned short) (*((unsigned long *) x86Registers[REG_FCS].valptr) & 0xFFFF);

  fpuState->fooff = *((long *) x86Registers[REG_FOOFF].valptr);
  fpuState->foseg = *((long *) x86Registers[REG_FOSEG].valptr);

  memcpy(fpuState->stptr,
         (unsigned char *) (ws->regContents.fpRegs.__data + 28),
         FPU_NUM_DATA_REGS * FPU_DATA_REG_SIZE);
#endif /* 0 */

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
x86writeRegisterDebug(struct debugWorkspace *ws,
                      struct x86RegInfo *rptr,
                      struct x86RegValue *regVal)

{
  if ((rptr->flags & R_GENERAL) ||
      ((rptr->flags & R_FPU) && !(rptr->flags & R_FPU_DATA)))
  {
    /*
     * update ws->regContents.values with the new value of type long
     */
    *((unsigned long *) rptr->valptr) = regVal->lvalue;
  }
  else if (rptr->flags & R_FPU_DATA)
  {
    /*
     * update the appropriate register location with the new value
     * of the fpu data register
     */
    memcpy((unsigned char *)rptr->valptr, regVal->stptr, FPU_DATA_REG_SIZE);
  }

  /*
   * Call ptrace to set the actual register
   */
  if (ptrace(PT_SETREGS, ws->pid, (caddr_t) &(ws->regContents.Regs), 0) != 0)
    return (0); /* error */

  if (ptrace(PT_SETFPREGS, ws->pid, (caddr_t) &(ws->regContents.fpRegs), 0) != 0)
    return (0); /* error */

  return (1);
} /* x86writeRegistersDebug() */
