/*
 * libDebug
 *
 * Copyright (C) 2000-2003 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: freebsd-x86.c,v 1.1.1.1 2004/04/26 00:40:59 pa33 Exp $
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <string.h>
#include <signal.h>

/*
 * Top-level includes
 */
#include "args.h"
#include "break.h"
#include "libDebug.h"

#ifdef OS_DARWIN
#include <mach/mach.h>
#include <mach/machine/thread_status.h>
#else
#include <sys/ptrace.h>
#include <machine/reg.h>
#endif

/*
 * libString includes
 */
#include "alloc.h"
#include "Strn.h"

// Darwin ptrace() replacements: Read and Write uint32_t.
uint32_t darwin_PtraceRead(pid_t pid, caddr_t addr, int data) {
  kern_return_t err;
  mach_port_t task;
  uint32_t val = 0, count = 4;

  err = task_for_pid(mach_task_self(), pid, &task);
  if (err != KERN_SUCCESS)
    err = 1;

  err = task_suspend(task);
  if (err != KERN_SUCCESS) {
  }
  err = vm_read(task, (vm_address_t)addr, 4, (vm_offset_t *)&val, &count);

  err = task_resume(task);
  if (err != KERN_SUCCESS) {
  }

  return val;
}

int darwin_PtraceWrite(pid_t pid, caddr_t addr, int data) {
  kern_return_t err;
  mach_port_t task;
  uint32_t val = data, count = 4;

  err = task_for_pid(mach_task_self(), pid, &task);
  if (err != KERN_SUCCESS)
    err = 1;

  err = task_suspend(task);
  if (err != KERN_SUCCESS) {
  }
  err = vm_write(task, (vm_address_t)addr, (pointer_t)&val, (mach_msg_type_number_t)count);

  err = task_resume(task);
  if (err != KERN_SUCCESS) {
  }

  return 0;
}

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
  int ii; /* looping */

  /*
   * Set up pointers to general registers
   */

  x86Registers[REG_EAX].valptr = (void *) &(ws->regContents.state.uts.ts32.__eax);
  x86Registers[REG_EBX].valptr = (void *) &(ws->regContents.state.uts.ts32.__ebx);
  x86Registers[REG_ECX].valptr = (void *) &(ws->regContents.state.uts.ts32.__ecx);
  x86Registers[REG_EDX].valptr = (void *) &(ws->regContents.state.uts.ts32.__edx);
  x86Registers[REG_ESP].valptr = (void *) &(ws->regContents.state.uts.ts32.__esp);
  x86Registers[REG_EBP].valptr = (void *) &(ws->regContents.state.uts.ts32.__ebp);
  x86Registers[REG_ESI].valptr = (void *) &(ws->regContents.state.uts.ts32.__esi);
  x86Registers[REG_EDI].valptr = (void *) &(ws->regContents.state.uts.ts32.__edi);
  x86Registers[REG_DS].valptr = (void *) &(ws->regContents.state.uts.ts32.__ds);
  x86Registers[REG_ES].valptr = (void *) &(ws->regContents.state.uts.ts32.__es);
  x86Registers[REG_FS].valptr = (void *) &(ws->regContents.state.uts.ts32.__fs);
  x86Registers[REG_GS].valptr = (void *) &(ws->regContents.state.uts.ts32.__gs);
  x86Registers[REG_SS].valptr = (void *) &(ws->regContents.state.uts.ts32.__ss);
  x86Registers[REG_CS].valptr = (void *) &(ws->regContents.state.uts.ts32.__cs);
  x86Registers[REG_EIP].valptr = (void *) &(ws->regContents.state.uts.ts32.__eip);
  x86Registers[REG_EFLAGS].valptr = (void *) &(ws->regContents.state.uts.ts32.__eflags);

  x86Registers[REG_AH].valptr = (void *) &(ws->regContents.state.uts.ts32.__eax);
  x86Registers[REG_AL].valptr = (void *) &(ws->regContents.state.uts.ts32.__eax);
  x86Registers[REG_AX].valptr = (void *) &(ws->regContents.state.uts.ts32.__eax);

  x86Registers[REG_BH].valptr = (void *) &(ws->regContents.state.uts.ts32.__ebx);
  x86Registers[REG_BL].valptr = (void *) &(ws->regContents.state.uts.ts32.__ebx);
  x86Registers[REG_BX].valptr = (void *) &(ws->regContents.state.uts.ts32.__ebx);

  x86Registers[REG_CH].valptr = (void *) &(ws->regContents.state.uts.ts32.__ecx);
  x86Registers[REG_CL].valptr = (void *) &(ws->regContents.state.uts.ts32.__ecx);
  x86Registers[REG_CX].valptr = (void *) &(ws->regContents.state.uts.ts32.__ecx);

  x86Registers[REG_DH].valptr = (void *) &(ws->regContents.state.uts.ts32.__edx);
  x86Registers[REG_DL].valptr = (void *) &(ws->regContents.state.uts.ts32.__edx);
  x86Registers[REG_DX].valptr = (void *) &(ws->regContents.state.uts.ts32.__edx);

  x86Registers[REG_SP].valptr = (void *) &(ws->regContents.state.uts.ts32.__esp);
  x86Registers[REG_BP].valptr = (void *) &(ws->regContents.state.uts.ts32.__ebp);
  x86Registers[REG_SI].valptr = (void *) &(ws->regContents.state.uts.ts32.__esi);
  x86Registers[REG_DI].valptr = (void *) &(ws->regContents.state.uts.ts32.__edi);

  x86Registers[REG_IP].valptr = (void *) &(ws->regContents.state.uts.ts32.__eip);
  x86Registers[REG_FLAGS].valptr = (void *) &(ws->regContents.state.uts.ts32.__eflags);

#ifdef FIXME
// See this: ufs.fs32._fpu
  /*
   * Floating point unit data registers
   */

  for (ii = 0; ii < FPU_NUM_DATA_REGS; ++ii)
  {
    x86Registers[REG_ST0 + ii].valptr =
      (void *) &(ws->regContents.state.ufs.fs32._fpu
//fpr_acc[ii][0]);
  }

  /*
   * Other floating point unit registers - see npx.h (struct env87)
   */
  x86Registers[REG_FCTRL].valptr = (void *) &(ws->regContents.fpRegs.fpr_env[0]);
  x86Registers[REG_FSTAT].valptr = (void *) &(ws->regContents.fpRegs.fpr_env[1]);
  x86Registers[REG_FTAG].valptr = (void *) &(ws->regContents.fpRegs.fpr_env[2]);
  x86Registers[REG_FIP].valptr = (void *) &(ws->regContents.fpRegs.fpr_env[3]);
  x86Registers[REG_FCS].valptr = (void *) &(ws->regContents.fpRegs.fpr_env[4]);
  x86Registers[REG_FOPCODE].valptr = (void *) ((char *) x86Registers[REG_FCS].valptr + sizeof(unsigned short));
  x86Registers[REG_FOOFF].valptr = (void *) &(ws->regContents.fpRegs.fpr_env[5]);
  x86Registers[REG_FOSEG].valptr = (void *) &(ws->regContents.fpRegs.fpr_env[6]);

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
      (void *) &(ws->regContents.fpRegs.fpr_acc[ii][0]);
  }
#endif
  return (1);
} /* x86initRegistersDebug() */

typedef int (state_callback_t)(struct debugWorkspace *ws, void *v, int *err);

void mach_set_thread_state(struct debugWorkspace *ws, state_callback_t callback, void *v, kern_return_t *err)

{
  assert(ws->pid != NOPID);

  /*
   * Make sure to always use 'U' here and not a temporary variable,
   * or the breakpoint code in x86Continue() will overwrite new
   * register contents with old ones when it calls
   * x86SetCurrentInstruction()
   */
  mach_port_t task;
  *err = task_for_pid(mach_task_self(), ws->pid, &task);
  if (*err != KERN_SUCCESS)
    *err = 1;

  *err = task_suspend(task);
  if (*err != KERN_SUCCESS) {
  }
  
  thread_act_port_array_t threadList;
  mach_msg_type_number_t threadCount;
  *err = task_threads(task, &threadList, &threadCount);
  if (*err != KERN_SUCCESS) {
  }

  mach_msg_type_number_t stateCount;
  stateCount = x86_THREAD_STATE_COUNT;
  *err = thread_get_state(threadList[0], 
                          x86_THREAD_STATE,
                          (thread_state_t)&ws->regContents.state,
                          &stateCount);
  if (*err != KERN_SUCCESS) {
  }
  
  if (callback(ws, err, v)) {
    *err = thread_set_state(threadList[0],
                            x86_THREAD_STATE,
                            (thread_state_t)&ws->regContents.state,
                            stateCount);
    if (*err != KERN_SUCCESS) {
    }
  }

  *err = task_resume(task);
  if (*err != KERN_SUCCESS) {
  }
}

/*
x86getCurrentInstruction()
  Determine the address of the next instruction to be executed (eip)
and return it.

Return: address of next instruction

Side effects: 'err' is set to 1 if ptrace() fails
*/

static int dummy(struct debugWorkspace *ws, void *v, int *err) { return 0; }

unsigned long
x86getCurrentInstruction(struct debugWorkspace *ws, int *err)
{
  mach_set_thread_state(ws, &dummy, NULL, err);
  return ((unsigned long) &ws->regContents.state.uts.ts32.__eip);
} /* x86getCurrentInstruction() */



/*
x86setCurrentInstruction()
  Set eip to the given address

Return: 1 if successful
        0 if not
*/

static int dummySet(struct debugWorkspace *ws, void *v, int *err)
{
  ws->regContents.state.uts.ts32.__eip = (unsigned int)v;
  return(1);
}

int
x86setCurrentInstruction(struct debugWorkspace *ws, unsigned long address)

{
  assert(ws->pid != NOPID);
  int err = 0;

  mach_set_thread_state(ws, &dummySet, (void *)address, &err);
  ws->regContents.state.uts.ts32.__eip = address;

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
  int err = 0;

  mach_set_thread_state(ws, &dummy, NULL, &err);

  /*
   * Save the location of our next instruction
   */
  ws->instructionPointer = ws->regContents.state.uts.ts32.__eip;

  return (1);
} /* x86getRegistersDebug() */

#if 0

/*
x86readRegisterDebug()
  Read the contents of a specified register. Before calling this function,
x86getRegistersDebug() should be called to obtain the latest register contents via
ptrace

Inputs: ws     - debug workspace
        rptr   - pointer to a register in x86Registers[]
        regVal - store register value in here

Return: size of register in bytes

Side effects: regVal.lvalue is set to the register's value if it is a 16 or 32 bit
              register

              If it is a fpu data register, regVal.stptr is set to the position
              on the fpu data stack of the register
*/

size_t
x86readRegisterDebug(struct debugWorkspace *ws, struct x86RegInfo *rptr,
                     struct x86RegValue *regVal)

{
  int size;

  if (rptr->valptr == (void *) 0)
  {
    fprintf(stderr,
            "x86readRegisterDebug: valptr field of register %s is null\n",
            rptr->name);
    return (0);
  }

  if (rptr->flags & R_FPU_DATA)
  {
    /*
     * We want to read one of the fpu data registers. The appropriate
     * location in fpr_acc[] was computed for each data register in
     * x86initRegistersDebug, so we just need to assign stptr to valptr.
     */
    regVal->stptr = (unsigned char *) rptr->valptr;
    size = 0;
  }
  else
  {
    if (rptr->flags & R_BITS8)
    {
      /*
       * We only get here from x86setRegisterDebug(), and we do not want to "and"
       * this value to strip off the last byte, since we may be trying to set
       * the ah/bh/ch/dh registers which don't occur in the last byte. So let
       * x86setRegisterDebug() worry about that stuff.
       */
      size = 1;
      regVal->lvalue = *((unsigned long *) rptr->valptr);
    }
    else if (rptr->flags & R_BITS16)
    {
      size = 2;
      regVal->lvalue = *((unsigned long *) rptr->valptr) & 0xFFFF;
    }
    else if (rptr->flags & R_BITS32)
    {
      size = 4;
      regVal->lvalue = *((unsigned long *) rptr->valptr);
    }
    else
      return (0);
  }

  return (size);
} /* x86readRegisterDebug() */

#endif /* 0 */

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

  /*fpuState->fcs = (unsigned short) (ws->regContents.fpRegs.fpr_env[4] >> 16);*/
  /* last instruction pointer (segment) */
  fpuState->fcs = (unsigned short) (fcs & 0xFFFF);

  /* opcode */
  /*fpuState->fopcode = (unsigned short) (ws->regContents.fpRegs.fpr_env[4] & 0xFFFF);*/
  fpuState->fopcode = (unsigned short) (fcs >> 16);

  /* last data operand pointer (offset) */
  fpuState->fooff = (long) *((long *) x86Registers[REG_FOOFF].valptr);

  /* last data operand pointer (segment) */
  fpuState->foseg = (long) *((long *) x86Registers[REG_FOSEG].valptr);
#ifdef FIXME
  memcpy(fpuState->stptr,
         (unsigned char *) ws->regContents.fpRegs.fpr_acc,
         FPU_NUM_DATA_REGS * FPU_DATA_REG_SIZE);
#endif
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
     * update ws->regContents.values with the new value of type long
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
#ifdef FIXME
  if (ptrace(PT_SETREGS, ws->pid, (caddr_t) &(ws->regContents.Regs), 0) != 0)
    return (0); /* error */

  if (ptrace(PT_SETFPREGS, ws->pid, (caddr_t) &(ws->regContents.fpRegs), 0) != 0)
    return (0); /* error */
#endif

  return (1);
} /* x86writeRegistersDebug() */
