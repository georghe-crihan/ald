/*
 * libDebug
 *
 * Copyright (C) 2000 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: regs-x86.h,v 1.1.1.1 2004/04/26 00:41:04 pa33 Exp $
 */

#ifndef INCLUDED_regs_x86_h
#define INCLUDED_regs_x86_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#ifndef INCLUDED_libDebug_h
#include "libDebug.h"
#define INCLUDED_libDebug_h
#endif

#ifdef OS_LINUX

# ifndef INCLUDED_sys_user_h
#  include <sys/user.h>         /* struct user */
#  define INCLUDED_sys_user_h
# endif

#elif OS_BSD

# ifndef INCLUDED_machine_reg_h
#  include <machine/reg.h>      /* struct reg */
#  define INCLUDED_machine_reg_h
# endif

#endif

struct x86RegInfo
{
  char *name;           /* register name */

  /*
   * This value indicates the "chunk" position starting from
   * the right. What I mean by "chunk" is a group of eight
   * bits.
   *
   * For example, consider the eax register:
   *
   * eax     ax/ah                         al
   * b31 ... b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 b0
   *
   * The position of ah is 2, since it is 2 groups of eight bits
   * away from bit 0. The position of al is 1 since it is 1 group
   * of eight bits from bit 0. eax is position 4 and ax is position
   * 2.
   *
   * This serves a purpose when we want to modify ah or al only
   * so in our array we know the position at which that particular
   * register starts.
   */
  int position;

  unsigned int flags; /* R_xxx bitmasks */

  void *valptr;
};

#define FPU_NUM_DATA_REGS    8   /* number of fpu data registers */
#define FPU_DATA_REG_SIZE    10  /* size of a fpu data register in bytes */
#define MMX_NUM_REGS         8   /* number of mmx registers */
#define MMX_REG_SIZE         8   /* size of a mmx register in bytes */

struct x86fpuInfo
{
  unsigned short fctrl;   /* control register */
  unsigned short fstat;   /* status register */
  unsigned short ftag;    /* tag register */
  long fip;               /* floating point instruction pointer */
  unsigned short fcs;     /* floating code segment selector */
  unsigned short fopcode; /* opcode last executed */
  long fooff;             /* floating operand offset */
  long foseg;             /* floating operand segment selector */

  unsigned char stptr[FPU_NUM_DATA_REGS * FPU_DATA_REG_SIZE];
};

struct x86RegData
{
  void *valptr;    /* pointer to contents of register */
};

struct x86RegValue
{
  unsigned long lvalue;
  unsigned char *stptr;
};

/*
 * Register flags
 */
#define R_BITS8       (1 << 0) /* 8 bit register */
#define R_BITS16      (1 << 1) /* 16 bit register */
#define R_BITS32      (1 << 2) /* 32 bit register */
#define R_BITS64      (1 << 3) /* 64 bit register */
#define R_BITS80      (1 << 4) /* 80 bit register */
#define R_NODISPLAY   (1 << 5) /* do not output register/value */
#define R_GENERAL     (1 << 6) /* general register */
#define R_FPU         (1 << 7) /* fpu register */
#define R_FPU_DATA    (1 << 8) /* fpu data register */
#define R_MMX         (1 << 9) /* fpu data register */

/*
 * Indices into x86Registers[]
 */

#define REG_EAX          0
#define REG_EBX          1
#define REG_ECX          2
#define REG_EDX          3
#define REG_ESP          4
#define REG_EBP          5
#define REG_ESI          6
#define REG_EDI          7
#define REG_DS           8
#define REG_ES           9
#define REG_FS           10
#define REG_GS           11
#define REG_SS           12
#define REG_CS           13
#define REG_EIP          14
#define REG_EFLAGS       15

#define REG_ENDGENERAL   16   /* marks the end of the general registers */

#define REG_AH           17
#define REG_AL           18
#define REG_AX           19
#define REG_BH           20
#define REG_BL           21
#define REG_BX           22
#define REG_CH           23
#define REG_CL           24
#define REG_CX           25
#define REG_DH           26
#define REG_DL           27
#define REG_DX           28
#define REG_SP           29
#define REG_BP           30
#define REG_SI           31
#define REG_DI           32
#define REG_IP           33
#define REG_FLAGS        34

#define REG_ST0          35  /* fpu data registers */
#define REG_ST1          36
#define REG_ST2          37
#define REG_ST3          38
#define REG_ST4          39
#define REG_ST5          40
#define REG_ST6          41
#define REG_ST7          42
#define REG_FCTRL        43  /* control register */
#define REG_FSTAT        44  /* status register */
#define REG_FTAG         45  /* tag register */
#define REG_FIP          46  /* floating point instruction pointer */
#define REG_FCS          47  /* floating code segment selector */
#define REG_FOPCODE      48  /* opcode last executed */
#define REG_FOOFF        49  /* floating operand offset */
#define REG_FOSEG        50  /* floating operand segment selector */

#define REG_MM0          51  /* mmx registers */
#define REG_MM1          52
#define REG_MM2          53
#define REG_MM3          54
#define REG_MM4          55
#define REG_MM5          56
#define REG_MM6          57
#define REG_MM7          58

struct x86RegisterContents
{

#ifdef OS_LINUX

  struct user Regs;

#elif OS_BSD

  struct reg Regs;
  struct fpreg fpRegs;

#endif

};

/*
 * Prototypes
 */

struct debugWorkspace;

int x86findRegisterDebug(struct debugWorkspace *ws, char *name);
size_t x86readRegisterDebug(struct debugWorkspace *ws, struct x86RegInfo *rptr,
                            struct x86RegValue *regVal);
int x86printRegistersDebug(struct debugWorkspace *ws, int regindex, unsigned int flags,
                           void (*callback)(), void *callbackArgs);
int x86setRegisterDebug(struct debugWorkspace *ws, int regindex, char *value);
int x86getFlagsDebug(struct debugWorkspace *ws, char *flags);
long x86readIntRegisterDebug(struct debugWorkspace *ws, int regindex);

/*
 * External declarations
 */

extern struct x86RegInfo x86Registers[];

#endif /* INCLUDED_regs_x86_h */
