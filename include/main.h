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
 * $Id: main.h,v 1.3 2004/10/10 05:29:48 pa33 Exp $
 */

#ifndef INCLUDED_main_h
#define INCLUDED_main_h

#include "command.h"

#ifndef INCLUDED_print_h
#include "print.h"
#define INCLUDED_print_h
#endif

#include "rc.h"
#include "terminal.h"

#ifndef INCLUDED_libDebug_libDebug_h
#include "libDebug.h"
#define INCLUDED_libDebug_libDebug_h
#endif

#ifndef INCLUDED_libDASM_libDASM_h
#include "libDASM.h"
#define INCLUDED_libDASM_libDASM_h
#endif

#ifndef INCLUDED_libOFF_libOFF_h
#include "libOFF.h"         /* struct offWorkspace */
#define INCLUDED_libOFF_libOFF_h
#endif

struct aldWorkspace
{
  char *filename;                    /* command line filename, if any */

  /*
   * File loading parameters
   */
  void *MapPtr;                      /* pointer to mapped memory */
  size_t MappedSize;                 /* size of mapped memory */

  int objectFileDescriptor;          /* file we are debugging */
  char *objectFileName;              /* name of file we are debugging */

  unsigned int virtualFileAddress;   /* virtual address of file beginning */
  unsigned int virtualEntryPoint;    /* virtual address of entry point */
  unsigned int entryPoint;           /* entry point of object file */

  unsigned int objectFileOffset;     /* file offset */
  unsigned int virtualObjectFileOffset; /* virtual address of current offset */

  unsigned int settings;             /* boolean settings (see set.h) */
  unsigned int flags;                /* bitmask flags (AW_xxx) */
  unsigned int stepDisplayFlags;     /* regs to display on singlesteps (DB_REGFL_xxx) */

  /*
   * Disassemble variables
   */
  unsigned long nextInstruction;     /* next instruction to disassemble */
  unsigned int currentSectionStart;  /* start of current section */

  /*
   * This list contains pointers to memory which need to
   * be freed in case the path of execution takes an
   * unexpected turn. For example, in the "examine" command,
   * memory is allocated for the buffer which contains the
   * memory dump. If the user stops looking at the memory output
   * before it completes (either ^C or hitting 'q' during the
   * pause-print screen), that memory won't be freed normally
   * by c_examine, since a longjmp() is performed back to
   * procCommand(). Therefore, when procCommand() notices that
   * longjmp() was used, it will free any items in this list.
   */
  struct genericList *toBeFreed;

  /*
   * This list contains pointers to address ranges which we
   * will dump from memory after each single step. See the
   * "help display" info
   */
  struct genericList *stepDisplayList;
  unsigned int stepDisplayNum;

  struct commandWorkspace *commandWorkspace_p;
  struct printWorkspace *printWorkspace_p;
  struct rcWorkspace *rcWorkspace_p;
  struct terminalWorkspace *terminalWorkspace_p;

  struct debugWorkspace *debugWorkspace_p;
  struct disasmWorkspace *disasmWorkspace_p;
  struct offWorkspace *offWorkspace_p;
};

#define AW_ATTACHED           (1 << 0)  /* attached to running process */
#define AW_FILELOADED         (1 << 1)  /* file loaded into memory */

#define awSetAttached(x)      ((x)->flags |= AW_ATTACHED)
#define awSetFileLoaded(x)    ((x)->flags |= AW_FILELOADED)

#define awIsAttached(x)       ((x)->flags & AW_ATTACHED)
#define awIsFileLoaded(x)     ((x)->flags & AW_FILELOADED)

#define awClearAttached(x)    ((x)->flags &= ~AW_ATTACHED)
#define awClearFileLoaded(x)  ((x)->flags &= ~AW_FILELOADED)

/*
 * Prototypes
 */

struct aldWorkspace *initALD(int argc, char *argv[]);
void termALD(struct aldWorkspace *ws);
int procALD(struct aldWorkspace *ws);

#endif /* INCLUDED_main_h */
