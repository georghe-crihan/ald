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
 * $Id: regs-x86.c,v 1.2 2004/10/09 17:34:15 pa33 Exp $
 *
 * This module contains routines dealing with x86 registers which are common to
 * all operating systems.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/*
 * Top-level includes
 */

#include "libDebug.h"

#include "Strn.h"

/*
 * List of x86 registers - the elements in this array are ordered to
 * correspond to the REG_xxx indices defined in regs-x86.h
 */
struct x86RegInfo x86Registers[] = {
  { "eax", 4, R_BITS32|R_GENERAL, (void *) 0 },
  { "ebx", 4, R_BITS32|R_GENERAL, (void *) 0 },
  { "ecx", 4, R_BITS32|R_GENERAL, (void *) 0 },
  { "edx", 4, R_BITS32|R_GENERAL, (void *) 0 },
  { "esp", 4, R_BITS32|R_GENERAL, (void *) 0 },
  { "ebp", 4, R_BITS32|R_GENERAL, (void *) 0 },
  { "esi", 4, R_BITS32|R_GENERAL, (void *) 0 },
  { "edi", 4, R_BITS32|R_GENERAL, (void *) 0 },
  { "ds", 2, R_BITS16|R_GENERAL, (void *) 0 },
  { "es", 2, R_BITS16|R_GENERAL, (void *) 0 },
  { "fs", 2, R_BITS16|R_GENERAL, (void *) 0 },
  { "gs", 2, R_BITS16|R_GENERAL, (void *) 0 },
  { "ss", 2, R_BITS16|R_GENERAL, (void *) 0 },
  { "cs", 2, R_BITS16|R_GENERAL, (void *) 0 },
  { "eip", 4, R_BITS32|R_GENERAL, (void *) 0 },
  { "eflags", 4, R_BITS32|R_GENERAL, (void *) 0 },

  { "null", 0, 0, (void *) 0 },                            /* REG_ENDGENERAL */

  /*
   * These can be modified, but do not display them when
   * the user wishes to display all registers
   */
  { "ah", 2, R_BITS8|R_NODISPLAY|R_GENERAL, (void *) 0 },
  { "al", 1, R_BITS8|R_NODISPLAY|R_GENERAL, (void *) 0 },
  { "ax", 2, R_BITS16|R_NODISPLAY|R_GENERAL, (void *) 0 },

  { "bh", 2, R_BITS8|R_NODISPLAY|R_GENERAL, (void *) 0 },
  { "bl", 1, R_BITS8|R_NODISPLAY|R_GENERAL, (void *) 0 },
  { "bx", 2, R_BITS16|R_NODISPLAY|R_GENERAL, (void *) 0 },

  { "ch", 2, R_BITS8|R_NODISPLAY|R_GENERAL, (void *) 0 },
  { "cl", 1, R_BITS8|R_NODISPLAY|R_GENERAL, (void *) 0 },
  { "cx", 2, R_BITS16|R_NODISPLAY|R_GENERAL, (void *) 0 },

  { "dh", 2, R_BITS8|R_NODISPLAY|R_GENERAL, (void *) 0 },
  { "dl", 1, R_BITS8|R_NODISPLAY|R_GENERAL, (void *) 0 },
  { "dx", 2, R_BITS16|R_NODISPLAY|R_GENERAL, (void *) 0 },

  { "sp", 2, R_BITS16|R_NODISPLAY|R_GENERAL, (void *) 0 },
  { "bp", 2, R_BITS16|R_NODISPLAY|R_GENERAL, (void *) 0 },
  { "si", 2, R_BITS16|R_NODISPLAY|R_GENERAL, (void *) 0 },
  { "di", 2, R_BITS16|R_NODISPLAY|R_GENERAL, (void *) 0 },

  { "ip", 2, R_BITS16|R_NODISPLAY|R_GENERAL, (void *) 0 },

  { "flags", 2, R_BITS16|R_NODISPLAY|R_GENERAL, (void *) 0 },

  /*
   * FPU (Floating Point Unit) registers
   */

  { "st0", 0, R_BITS80|R_FPU|R_FPU_DATA, (void *) 0 },
  { "st1", 0, R_BITS80|R_FPU|R_FPU_DATA, (void *) 0 },
  { "st2", 0, R_BITS80|R_FPU|R_FPU_DATA, (void *) 0 },
  { "st3", 0, R_BITS80|R_FPU|R_FPU_DATA, (void *) 0 },
  { "st4", 0, R_BITS80|R_FPU|R_FPU_DATA, (void *) 0 },
  { "st5", 0, R_BITS80|R_FPU|R_FPU_DATA, (void *) 0 },
  { "st6", 0, R_BITS80|R_FPU|R_FPU_DATA, (void *) 0 },
  { "st7", 0, R_BITS80|R_FPU|R_FPU_DATA, (void *) 0 },

  { "fctrl", 2, R_BITS16|R_FPU, (void *) 0 },
  { "fstat", 2, R_BITS16|R_FPU, (void *) 0 },
  { "ftag", 2, R_BITS16|R_FPU, (void *) 0 },
  { "fipoff", 4, R_BITS32|R_FPU, (void *) 0 },
  { "fipseg", 2, R_BITS16|R_FPU, (void *) 0 },
  { "fopcode", 2, R_BITS16|R_FPU, (void *) 0 },
  { "fooff", 4, R_BITS32|R_FPU, (void *) 0 },
  { "foseg", 4, R_BITS32|R_FPU, (void *) 0 },

  /*
   * MMX registers
   */

  { "mm0", 0, R_BITS64|R_MMX, (void *) 0 },
  { "mm1", 0, R_BITS64|R_MMX, (void *) 0 },
  { "mm2", 0, R_BITS64|R_MMX, (void *) 0 },
  { "mm3", 0, R_BITS64|R_MMX, (void *) 0 },
  { "mm4", 0, R_BITS64|R_MMX, (void *) 0 },
  { "mm5", 0, R_BITS64|R_MMX, (void *) 0 },
  { "mm6", 0, R_BITS64|R_MMX, (void *) 0 },
  { "mm7", 0, R_BITS64|R_MMX, (void *) 0 },

  { 0, 0, 0, (void *) 0 }
};

/*
x86findRegisterDebug()
  Attempt to locate the given register name in x86Registers[]

Return: index in x86Registers[] if found
        -1 if not
*/

int
x86findRegisterDebug(struct debugWorkspace *ws, char *name)

{
  struct x86RegInfo *rptr;

  for (rptr = x86Registers; rptr->name; ++rptr)
  {
    if (!Strcasecmp(name, rptr->name))
      return ((int) (rptr - x86Registers));
  }

  /*
   * Not found
   */
  return (-1);
} /* x86findRegisterDebug() */

/*
x86readRegisterDebug()
  Read the contents of a specified register. Before calling this
function, x86getRegistersDebug() should be called to obtain the
latest register contents via ptrace

Inputs: ws     - debug workspace
        rptr   - pointer to a register in x86Registers[]
        regVal - store register value in here

Return: size of register in bytes

Side effects: regVal.lvalue is set to the register's value if it
              is a 16 or 32 bit register

              If it is a fpu data register, regVal.stptr is set to
              the position on the fpu data stack of the register
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

  if ((rptr->flags & R_FPU_DATA) || (rptr->flags & R_MMX))
  {
    /*
     * We want to read one of the fpu data registers. The appropriate
     * location in i387.st_space was computed for each data register in
     * x86initRegistersDebug, so we just need to assign stptr to valptr.
     */
    regVal->stptr = (unsigned char *) rptr->valptr;
    size = 8;
  }
  else
  {
    if (rptr->flags & R_BITS8)
    {
      /*
       * We only get here from x86setRegisterDebug(), and we do not
       * want to "and" this value to strip off the last byte, since
       * we may be trying to set the ah/bh/ch/dh registers which don't
       * occur in the last byte. So let x86setRegisterDebug() worry
       * about that stuff.
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

/*
x86printRegistersDebug()
  Traverse the list of registers and call a given callback function
with each register's name and value.

Inputs: ws           - debug workspace
        regindex     - optional index of x86Registers to display
                       (-1 to display all registers)
        flags        - flags (see REGFL_xxx in libDebug.h)
        callback     - callback function:
                       void *callback(struct debugRegisterInfo *regInfo,
                                      void *args);
        callbackArgs - arguments to callback function

Return: 1 if successful
        0 upon ptrace error
*/

int
x86printRegistersDebug(struct debugWorkspace *ws, int regindex,
                       unsigned int flags, void (*callback)(),
                       void *callbackArgs)

{
  struct x86fpuInfo *fpuState;
  struct x86RegInfo *rptr;
  unsigned char *stptr;
  char *bufptr;
  int ii, jj;
  int shr;
  unsigned long regvalue;
  size_t size;
  struct x86RegValue regVal;
  unsigned int regFlags;
  int needbreak;

  /*
   * Grab the process' registers
   */
  if (!x86getRegistersDebug(ws))
    return (0);

  needbreak = 0;

  if (regindex < 0)
  {
    /*
     * They want to display all registers - traverse register list
     */

    if (flags & DB_REGFL_DISPLAY_GENERAL)
    {
      /*
       * Print out the general registers first
       */
      ws->regInfo.flags |= DB_RI_GENERAL;


      for (ii = 0; ii < REG_ENDGENERAL; ++ii)
      {
        rptr = x86Registers + ii;

        if (rptr->flags & R_NODISPLAY)
          continue;


        size = x86readRegisterDebug(ws,
                                    rptr,
                                    &regVal);

        ws->regInfo.size = size;

        ws->regInfo.value = regVal.lvalue;
        strcpy(ws->regInfo.name, rptr->name);


        /*
         * Call our callback function with the register information
         */
        (*callback)(&(ws->regInfo), callbackArgs);
      } /* for (ii = 0; ii < REG_ENDGENERAL; ++ii) */

      ws->regInfo.flags &= ~DB_RI_GENERAL;

      needbreak = 1;
    } /* if (flags & DB_REGFL_DISPLAY_GENERAL) */

    if (flags & DB_REGFL_DISPLAY_FPREGS)
    {
      if (needbreak)
      {
        ws->regInfo.flags |= DB_RI_BREAK;
        (*callback)(&(ws->regInfo), callbackArgs);
        ws->regInfo.flags &= ~DB_RI_BREAK;

        needbreak = 0;
      }

      /*
       * Get and print out fpu registers
       */
      fpuState = (struct x86fpuInfo *) ws->fpuState;
      if (!x86readFPUDebug(ws, fpuState))
        return (0);

#if 0 /* big endian */
      stptr = fpuState->stptr;
#endif

      /*
       * Traverse the list of floating point data registers
       */

      ws->regInfo.flags |= DB_RI_FPU_DATA;
      ws->regInfo.size = 2;

      for (ii = 0; ii < FPU_NUM_DATA_REGS; ++ii)
      {
        sprintf(ws->regInfo.name, "st%d", ii);

        bufptr = ws->regInfo.hexvalue;
        bufptr += sprintf(bufptr, "%s", "0x");

#if 0 /* big endian */
        for (jj = 0; jj < FPU_DATA_REG_SIZE; ++jj)
          bufptr += sprintf(bufptr, "%02x", *stptr++);
#endif

        stptr = fpuState->stptr + ((ii + 1) * FPU_DATA_REG_SIZE - 1);
        for (jj = 0; jj < FPU_DATA_REG_SIZE; ++jj)
          bufptr += sprintf(bufptr, "%02x", *stptr--);

        ws->regInfo.rawbuf = fpuState->stptr + ii*FPU_DATA_REG_SIZE;

        (*callback)(&(ws->regInfo), callbackArgs);
      } /* for (ii = 0; ii < FPU_NUM_DATA_REGS; ++ii) */

      ws->regInfo.flags &= ~DB_RI_FPU_DATA;

      ws->regInfo.size = 2;

      strcpy(ws->regInfo.name, x86Registers[REG_FCTRL].name);
      ws->regInfo.value = (unsigned long) fpuState->fctrl;
      (*callback)(&(ws->regInfo), callbackArgs);

      strcpy(ws->regInfo.name, x86Registers[REG_FSTAT].name);
      ws->regInfo.value = (unsigned long) fpuState->fstat;
      (*callback)(&(ws->regInfo), callbackArgs);

      strcpy(ws->regInfo.name, x86Registers[REG_FTAG].name);
      ws->regInfo.value = (unsigned long) fpuState->ftag;
      (*callback)(&(ws->regInfo), callbackArgs);

      ws->regInfo.size = 2;
      strcpy(ws->regInfo.name, x86Registers[REG_FCS].name);
      ws->regInfo.value = fpuState->fcs;
      (*callback)(&(ws->regInfo), callbackArgs);

      ws->regInfo.size = 4;
      strcpy(ws->regInfo.name, x86Registers[REG_FIP].name);
      ws->regInfo.value = fpuState->fip;
      (*callback)(&(ws->regInfo), callbackArgs);

      ws->regInfo.size = 1;
      strcpy(ws->regInfo.name, x86Registers[REG_FOSEG].name);
      ws->regInfo.value = fpuState->foseg;
      (*callback)(&(ws->regInfo), callbackArgs);

      ws->regInfo.size = 4;
      strcpy(ws->regInfo.name, x86Registers[REG_FOOFF].name);
      ws->regInfo.value = fpuState->fooff;
      (*callback)(&(ws->regInfo), callbackArgs);

      ws->regInfo.size = 2;
      strcpy(ws->regInfo.name, x86Registers[REG_FOPCODE].name);
      ws->regInfo.value = fpuState->fopcode;
      (*callback)(&(ws->regInfo), callbackArgs);

      needbreak = 1;
    } /* if (flags & DB_REGFL_DISPLAY_FPREGS) */

    if (flags & DB_REGFL_DISPLAY_MMXREGS)
    {
      /*
       * Let the external program know there is a new batch of
       * registers coming
       */
      if (needbreak)
      {
        ws->regInfo.flags |= DB_RI_BREAK;
        (*callback)(&(ws->regInfo), callbackArgs);
        ws->regInfo.flags &= ~DB_RI_BREAK;

        needbreak = 0;
      }

      /*
       * Get and print out mmx registers
       */
      fpuState = (struct x86fpuInfo *) ws->fpuState;
      if (!x86readFPUDebug(ws, fpuState))
        return (0);

      ws->regInfo.flags |= DB_RI_MMX;
      ws->regInfo.size = 4;

      for (ii = 0; ii < MMX_NUM_REGS; ++ii)
      {
        sprintf(ws->regInfo.name, "mm%d", ii);

        bufptr = ws->regInfo.hexvalue;
        bufptr += sprintf(bufptr, "%s", "0x");

        stptr = fpuState->stptr + ((ii + 1) * FPU_DATA_REG_SIZE - 1) - 2;
        for (jj = 0; jj < MMX_REG_SIZE; ++jj)
          bufptr += sprintf(bufptr, "%02x", *stptr--);

        (*callback)(&(ws->regInfo), callbackArgs);
      } /* for (ii = 0; ii < NUM_MMX_REGS; ++ii) */

      ws->regInfo.flags &= ~DB_RI_MMX;
    } /* if (flags & DB_REGFL_DISPLAY_MMXREGS) */

    return (1);
  } /* if (regindex < 0) */

  /*
   * They want a specific register
   */

  rptr = x86Registers + regindex;

  regvalue = 0;
  regFlags = 0;

  size = x86readRegisterDebug(ws, rptr, &regVal);
  if (size == 0)
    return (0); /* something went wrong */

  if (rptr->flags & R_BITS8)
  {
    if (rptr->position == 1)
      shr = 0;
    else
    {
      assert(rptr->position == 2);
      shr = 8;
    }

    regvalue = (regVal.lvalue >> shr) & 0xFF;
  }
  else if (rptr->flags & R_BITS16)
  {
    if (rptr->position == 2)
      shr = 0;
    else
    {
      assert(rptr->position == 4);
      shr = 16;
    }

    regvalue = (regVal.lvalue >> shr) & 0xFFFF;
  }
  else if (rptr->flags & R_BITS32)
  {
    regvalue = regVal.lvalue;
  }
  else if ((rptr->flags & R_BITS64) && (rptr->flags & R_MMX))
  {
    bufptr = ws->regInfo.hexvalue;
    bufptr += sprintf(bufptr, "%s", "0x");

    stptr = regVal.stptr + FPU_DATA_REG_SIZE - 3;
    for (jj = 0; jj < MMX_REG_SIZE; ++jj)
      bufptr += sprintf(bufptr, "%02x", *stptr--);

    ws->regInfo.rawbuf = regVal.stptr;

    regFlags |= DB_RI_MMX;
  }
  else if ((rptr->flags & R_BITS80) && (rptr->flags & R_FPU_DATA))
  {
    bufptr = ws->regInfo.hexvalue;
    bufptr += sprintf(bufptr, "%s", "0x");

    stptr = regVal.stptr + FPU_DATA_REG_SIZE - 1;
    for (jj = 0; jj < FPU_DATA_REG_SIZE; ++jj)
      bufptr += sprintf(bufptr, "%02x", *stptr--);

    ws->regInfo.rawbuf = regVal.stptr;

    regFlags |= DB_RI_FPU_DATA;
  }
  else
    return (0);

  strcpy(ws->regInfo.name, rptr->name);
  ws->regInfo.value = regvalue;
  ws->regInfo.size = size;

  ws->regInfo.flags |= regFlags;

  (*callback)(&(ws->regInfo), callbackArgs);

  ws->regInfo.flags &= ~regFlags;

  return (1);
} /* x86printRegistersDebug() */

/*
x86setRegisterDebug()
  Set a register to a given value

Inputs: ws       - debug workspace
        regindex - index of x86Registers[] corresponding to the
                   register we want to modify
        value    - new value in ascii format

Return: 1 if successful
        0 if general error
        -1 if ptrace error occurs
        -2 if invalid value is given
*/

int
x86setRegisterDebug(struct debugWorkspace *ws, int regindex, char *value)

{
  struct x86RegInfo *rptr;
  unsigned int andmask; /* mask to and old register value with */
  int shl;              /* number of bits to shift new value left */
  unsigned long lval;   /* long value if general register */
  long double dval;     /* double value if fpu data register (*must* be long double) */
  unsigned long newval;
  unsigned long curval;
  size_t size;
  struct x86RegValue regVal;
  char *endptr;

  assert(ws->pid != NOPID);
  assert(regindex >= 0);

  rptr = x86Registers + regindex;

  if ((rptr->flags & R_GENERAL) ||
      ((rptr->flags & R_FPU) && !(rptr->flags & R_FPU_DATA)))
  {
    lval = strtoul(value, &endptr, 0);
    if ((endptr == value) || (*endptr != '\0'))
      return (-2); /* invalid value */

    if (rptr->flags & R_BITS8)
    {
      newval = lval & 0xff;
      if (rptr->position == 1)
      {
        /*
         * cases like al/bl/cl/dl
         */
        andmask = 0xffffff00;
        shl = 0;
      }
      else if (rptr->position == 2)
      {
        /*
         * cases like ah/bh/ch/dh
         */
        andmask = 0xffff00ff;
        shl = 8;
      }
      else
        return (0);
    }
    else if (rptr->flags & R_BITS16)
    {
      newval = lval & 0xffff;
      if (rptr->position == 2)
      {
        andmask = 0xffff0000;
        shl = 0;
      }
      else if (rptr->position == 4)
      {
        andmask = 0x0000ffff;
        shl = 8;
      }
      else
        return (0);
    }
    else if (rptr->flags & R_BITS32)
    {
      assert(rptr->position == 4);

      newval = lval;

      andmask = 0;
      shl = 0;
    }
    else
    {
      fprintf(stderr,
              "x86setRegisterDebug: invalid register flags: 0x%08X\n",
              rptr->flags);
      return (0); /* should never happen */
    }

    /* get the current value of this register */
    size = x86readRegisterDebug(ws, rptr, &regVal);
    curval = regVal.lvalue;

    /* clear space for the register we are about to set */
    curval &= andmask;

    /* set the register */
    curval |= (newval << shl);

    /* set the actual register */
    regVal.lvalue = curval;
    if (!x86writeRegisterDebug(ws, rptr, &regVal))
      return (-1); /* ptrace error */
  } /* if (rptr->flags & R_GENERAL) */
  else if (rptr->flags & R_FPU_DATA)
  {
    dval = (long double) strtod(value, &endptr);
    if ((endptr == value) || (*endptr != '\0'))
      return (-2); /* invalid value */

    /*
     * set the fpu data register
     */

    regVal.stptr = (unsigned char *) &dval;

    if (!x86writeRegisterDebug(ws, rptr, &regVal))
      return (-1); /* ptrace error */
  } /* if (rptr->flags & R_FPU_DATA) */
  else if (rptr->flags & R_MMX)
  {
    printf("setting mmx reg, value = %s\n", value);
  } /* if (rptr->flags & R_MMX) */

  return (1);
} /* x86setRegisterDebug() */

/*
x86getFlagsDebug()
  Get flags register settings

Inputs: ws    - debug workspace
        flags - where to store human readable settings

Return: 1 if successful
        0 if not
*/

int
x86getFlagsDebug(struct debugWorkspace *ws, char *flags)

{
  int ridx;
  long flval;
  size_t size;
  struct x86RegValue regVal;

  ridx = x86findRegisterDebug(ws, "eflags");
  if (ridx == (-1))
    return (0);

  size = x86readRegisterDebug(ws, x86Registers + ridx, &regVal);
  flval = regVal.lvalue;

  *flags = '\0';

  if (flval & (1 << 0))
    strcat(flags, "CF ");
  if (flval & (1 << 2))
    strcat(flags, "PF ");
  if (flval & (1 << 4))
    strcat(flags, "AF ");
  if (flval & (1 << 6))
    strcat(flags, "ZF ");
  if (flval & (1 << 7))
    strcat(flags, "SF ");
  if (flval & (1 << 8))
    strcat(flags, "TF ");
  if (flval & (1 << 9))
    strcat(flags, "IF ");
  if (flval & (1 << 10))
    strcat(flags, "DF ");
  if (flval & (1 << 11))
    strcat(flags, "OF ");
  if ((flval & (1 << 12)) && (flval & (1 << 13)))
    strcat(flags, "IOPL ");
  if (flval & (1 << 14))
    strcat(flags, "NT ");
  if (flval & (1 << 16))
    strcat(flags, "RF ");
  if (flval & (1 << 17))
    strcat(flags, "VM ");
  if (flval & (1 << 18))
    strcat(flags, "AC ");
  if (flval & (1 << 19))
    strcat(flags, "VIF ");
  if (flval & (1 << 20))
    strcat(flags, "VIP ");
  if (flval & (1 << 21))
    strcat(flags, "ID ");

  return (1);
} /* x86getFlagsDebug() */

/*
x86readRegisterDebug()
  XXX bingo XXX -- make this more general!
  This is provided for the command examine so it can access a register's contents
and use that as the memory location
*/

long
x86readIntRegisterDebug(struct debugWorkspace *ws, int regindex)

{
  struct x86RegInfo *rptr;
  struct x86RegValue regVal;

  if (regindex < 0)
    return (0);

  rptr = x86Registers + regindex;

  /*
   * Grab the process' registers
   */
  if (!x86getRegistersDebug(ws))
    return (0);

  x86readRegisterDebug(ws, rptr, &regVal);

  return (regVal.lvalue);
} /* x86readIntRegisterDebug() */
