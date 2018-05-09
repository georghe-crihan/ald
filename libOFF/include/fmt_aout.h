/*
 * Assembly Language Debugger
 *
 * Copyright (C) 2003 Patrick Alken
 * This program comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: fmt_aout.h,v 1.1.1.1 2004/04/26 00:40:41 pa33 Exp $
 */

#ifndef INCLUDED_libOFF_fmt_aout_h
#define INCLUDED_libOFF_fmt_aout_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#ifndef INCLUDED_a_out_h
#include <a.out.h>
#define INCLUDED_a_out_h
#endif

/*
 * Lame linux bandaids
 */
#if !defined(N_GETMAGIC) && defined(N_MAGIC)
# define N_GETMAGIC N_MAGIC
#endif

#if !defined(N_GETFLAG) && defined(N_FLAGS)
# define N_GETFLAG N_FLAGS
#endif

struct aoutParameters
{
  unsigned int entryPoint;
  unsigned int virtualEntryPoint;
};

struct aoutWorkspace
{
  struct exec *ExecHeader;     /* pointer to exec header */
};

struct aoutSectionInfo
{
  char *name;                  /* section name */
  unsigned int address;        /* section address */
  unsigned int offset;         /* file offset */
  unsigned int size;           /* section size */
};

#if 0 /* got these from OpenBSD exec_aout.h */

#define	MID_ZERO        0     /* unknown - implementation dependent */
#define	MID_SUN010      1     /* sun 68010/68020 binary */
#define	MID_SUN020      2     /* sun 68020-only binary */
#define	MID_PC386       100   /* 386 PC binary. (so quoth BFD) */
#define	MID_ROMPAOS     104   /* old IBM RT */
#define	MID_I386        134   /* i386 BSD binary */
#define	MID_M68K        135   /* m68k BSD binary with 8K page sizes */
#define	MID_M68K4K      136   /* DO NOT USE: m68k BSD binary with 4K page sizes */
#define	MID_NS32532     137   /* ns32532 */
#define	MID_SPARC       138   /* sparc */
#define	MID_PMAX        139   /* pmax */
#define	MID_VAX1K       140   /* vax 1k page size */
#define	MID_ALPHA       141   /* Alpha BSD binary */
#define	MID_MIPS        142   /* big-endian MIPS */
#define	MID_ARM6        143   /* ARM6 */
#define	MID_POWERPC     149   /* big-endian PowerPC */
#define	MID_VAX         150   /* vax */
#define	MID_SPARC64     151   /* LP64 sparc */
#define	MID_M88K        153   /* m88k BSD binary */ 
#define	MID_HPPA        154   /* hppa */
#define	MID_HP200       200   /* hp200 (68010) BSD binary */
#define	MID_HP300       300   /* hp300 (68020+68881) BSD binary */
#define	MID_HPUX        0x20C /* hp200/300 HP-UX binary */
#define	MID_HPUX800     0x20B /* hp800 HP-UX binary */

#endif /* 0 */

#define AOUTSEC_TXT     0
#define AOUTSEC_DATA    1
#define AOUTSEC_BSS     2

/*
 * Prototypes
 */

struct aoutWorkspace *initAOUT();
void termAOUT(struct aoutWorkspace *ws);
int checkAOUT(struct aoutWorkspace *ws, void *ptr, size_t size,
              struct aoutParameters *params, char *str);
int findSectionAOUT(struct aoutWorkspace *ws, char *name,
                    unsigned int address,
                    struct aoutSectionInfo *secinfo);
void printHeaderAOUT(struct aoutWorkspace *ws,
                     void (*callback)(void *, const char *, ...), void *args);
void printSectionInfoAOUT(struct aoutWorkspace *ws, char *name,
                          void (*callback)(void *, const char *, ...), void *args);

#endif /* INCLUDED_libOFF_fmt_aout_h */
