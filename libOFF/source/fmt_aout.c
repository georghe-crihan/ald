/*
 * libOFF
 *
 * Copyright (C) 2003 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: fmt_aout.c,v 1.1.1.1 2004/04/26 00:40:38 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <a.out.h>
#include <sys/types.h>
#include <assert.h>

#include "fmt_aout.h"

/*
 * Possible states of the magic number (N_GETMAGIC)
 */
static char MagicO[] = "OMAGIC";
static char MagicN[] = "NMAGIC";
static char MagicZ[] = "demand paged (ZMAGIC)";
static char MagicQ[] = "demand paged (QMAGIC)";

#if defined(EX_DYNAMIC) && defined(EX_PIC)

/*
 * Possible states of the flag field (N_GETFLAG)
 */
static char flagSO[] = "shared object";
static char flagDyn[] = "dynamic executable";
static char flagPIC[] = "position independent code";

#endif

char *aoutSections[] = {
  ".text",
  ".data",
  ".bss"
};

/*
initAOUT()
  Initialize an a.out workspace

Inputs: none

Return: pointer to new workspace
*/

struct aoutWorkspace *
initAOUT()

{
  struct aoutWorkspace *ws;

  ws = (struct aoutWorkspace *) malloc(sizeof(struct aoutWorkspace));
  if (!ws)
  {
    fprintf(stderr,
            "initAOUT: malloc failed: %s\n",
            strerror(errno));
    return (0);
  }

  memset(ws, '\0', sizeof(struct aoutWorkspace));

  return (ws);
} /* initAOUT() */

/*
termAOUT()
  Terminate an a.out workspace

Inputs: ws - workspace to terminate
*/

void
termAOUT(struct aoutWorkspace *ws)

{
  if (!ws)
    return;

  free(ws);
} /* termAOUT() */

/*
checkAOUT()
  Check whether a file is a.out

Inputs: ws     - a.out workspace
        ptr    - pointer to memory mapped file
        size   - size of file
        params - where to store file parameters
        str    - where to store identification string or errors

Return: 1 if file is a.out (id string goes in str)
        0 if not

Side effects: Upon successful identification, ws and params are modified to
              reflect various information we want to save for later
*/

int
checkAOUT(struct aoutWorkspace *ws, void *ptr, size_t size,
          struct aoutParameters *params, char *str)

{
  struct exec *ExecHeader;
  char *MagicId;
  char *FlagId;

  assert(ptr != 0);

  /*
   * Make sure file is big enough to contain the exec header
   */
  if (size < sizeof(struct exec))
    return (0);

  ExecHeader = (struct exec *) ptr;

  /*
   * Check for invalid magic number
   */
  if (N_BADMAG(*ExecHeader))
    return (0);

  MagicId = 0;
  if (N_GETMAGIC(*ExecHeader) == OMAGIC)
    MagicId = MagicO;
  else if (N_GETMAGIC(*ExecHeader) == NMAGIC)
    MagicId = MagicN;
  else if (N_GETMAGIC(*ExecHeader) == ZMAGIC)
    MagicId = MagicZ;
  else if (N_GETMAGIC(*ExecHeader) == QMAGIC)
    MagicId = MagicQ;

  if (!MagicId)
    return (0);

  str += sprintf(str, "a.out, %s", MagicId);

#if defined(EX_DYNAMIC) && defined(EX_PIC)

  FlagId = 0;
  if ((N_GETFLAG(*ExecHeader) & EX_DYNAMIC) &&
      (N_GETFLAG(*ExecHeader) & EX_PIC))
    FlagId = flagSO;
  else if (N_GETFLAG(*ExecHeader) & EX_DYNAMIC)
    FlagId = flagDyn;
  else if (N_GETFLAG(*ExecHeader) & EX_PIC)
    FlagId = flagPIC;

#else

  FlagId = "unknown";

#endif

  if (FlagId)
  {
    str += sprintf(str,
            ", %s",
            FlagId);
  }

  ws->ExecHeader = ExecHeader;

  params->entryPoint = params->virtualEntryPoint = ExecHeader->a_entry;

  /*
   * Everything checks out
   */
  return (1);
} /* checkAOUT() */

/*
findSectionAOUT()
  Find a section by name or address

Inputs: ws      - aout workspace
        name    - section name
        address - section address
        secinfo - where to store result

NOTE/BUG: searching by address not yet implemented

Return: 1 if section found
        0 if not
*/

int
findSectionAOUT(struct aoutWorkspace *ws, char *name,
                unsigned int address, struct aoutSectionInfo *secinfo)

{
  struct exec *ExecHeader;
  int ret;

  ExecHeader = ws->ExecHeader;
  ret = 0;

  if (!strcasecmp(name, ".text"))
  {
    ret = 1;

    secinfo->name = aoutSections[AOUTSEC_TXT];
    secinfo->address = N_TXTOFF(*ExecHeader);
    secinfo->offset = N_TXTOFF(*ExecHeader);
    secinfo->size = ExecHeader->a_text;
  }
  else if (!strcasecmp(name, ".data"))
  {
    ret = 1;

    secinfo->name = aoutSections[AOUTSEC_DATA];
    secinfo->address = N_DATOFF(*ExecHeader);
    secinfo->offset = N_DATOFF(*ExecHeader);
    secinfo->size = ExecHeader->a_data;
  }
  else if (!strcasecmp(name, ".bss"))
  {
    ret = 1;

    /*
     * The man pages aren't clear where the bss section is
     */
    secinfo->name = aoutSections[AOUTSEC_BSS];
    secinfo->address = 0;
    secinfo->offset = 0;
    secinfo->size = ExecHeader->a_bss;
  }

  return (ret);
} /* findSectionAOUT() */

/*
printHeaderAOUT()
  Print a.out header information

Inputs: ws       - a.out workspace
        callback - function to call to do printing
        args     - args to callback

Return: none
*/

void
printHeaderAOUT(struct aoutWorkspace *ws,
                void (*callback)(void *, const char *, ...),
                void *args)

{
  struct exec *ExecHeader;
  char *FlagId;
  char *MagicId;
  int dlen;

  /*
   * We can assume we have a valid a.out exec header
   */
  ExecHeader = ws->ExecHeader;

  dlen = 30;

  (*callback)(args,
              "%-*s a.out",
              dlen,
              "Object File Format:");

#if defined(EX_DYNAMIC) && defined(EX_PIC)

  FlagId = 0;
  if ((N_GETFLAG(*ExecHeader) & EX_DYNAMIC) &&
      (N_GETFLAG(*ExecHeader) & EX_PIC))
    FlagId = flagSO;
  else if (N_GETFLAG(*ExecHeader) & EX_DYNAMIC)
    FlagId = flagDyn;
  else if (N_GETFLAG(*ExecHeader) & EX_PIC)
    FlagId = flagPIC;
  else
    FlagId = "unknown";

#else

  FlagId = "unknown";

#endif

  (*callback)(args,
              "%-*s %s",
              dlen,
              "Object File Type:",
              FlagId);

  MagicId = 0;
  if (N_GETMAGIC(*ExecHeader) == OMAGIC)
    MagicId = MagicO;
  else if (N_GETMAGIC(*ExecHeader) == NMAGIC)
    MagicId = MagicN;
  else if (N_GETMAGIC(*ExecHeader) == ZMAGIC)
    MagicId = MagicZ;
  else if (N_GETMAGIC(*ExecHeader) == QMAGIC)
    MagicId = MagicQ;
  else
    MagicId = "unknown";

  (*callback)(args,
              "%-*s %s",
              dlen,
              "Object Loading Convention:",
              MagicId);

  (*callback)(args,
              "%-*s 0x%08X",
              dlen,
              "Entry Point:",
              ExecHeader->a_entry);

  (*callback)(args,
              "%-*s 0x%08X",
              dlen,
              "Text Segment Size:",
              ExecHeader->a_text);

  (*callback)(args,
              "%-*s 0x%08X",
              dlen,
              "Text Segment Offset:",
              N_TXTOFF(*ExecHeader));

  (*callback)(args,
              "%-*s 0x%08X",
              dlen,
              "Data Segment Size:",
              ExecHeader->a_data);

  (*callback)(args,
              "%-*s 0x%08X",
              dlen,
              "BSS Segment Size:",
              ExecHeader->a_bss);

  (*callback)(args,
              "%-*s 0x%08X",
              dlen,
              "Symbol Table Size:",
              ExecHeader->a_syms);

  (*callback)(args,
              "%-*s 0x%08X",
              dlen,
              "Symbol Table Offset:",
              N_SYMOFF(*ExecHeader));

  (*callback)(args,
              "%-*s 0x%08X",
              dlen,
              "String Table Offset:",
              N_STROFF(*ExecHeader));

  (*callback)(args,
              "%-*s 0x%08X",
              dlen,
              "Text Relocation Table Size:",
              ExecHeader->a_trsize);

  (*callback)(args,
              "%-*s 0x%08X",
              dlen,
              "Data Relocation Table Size:",
              ExecHeader->a_drsize);
} /* printHeaderAOUT() */

/*
printSectionInfoAOUT()
  Print a.out section information

Inputs: ws       - a.out workspace
        name     - optional section name
        callback - function to call to do printing
        args     - args to callback

Return: none
*/

void
printSectionInfoAOUT(struct aoutWorkspace *ws, char *name,
                     void (*callback)(void *, const char *, ...),
                     void *args)

{
  struct exec *ExecHeader;
  
  ExecHeader = ws->ExecHeader;

  if (name)
  {
    int dlen;

    /*
     * They want info on a specific section
     */

    dlen = 20; 

    if (!strcasecmp(name, ".text"))
    {
      (*callback)(args,
                  "%-*s %s",
                  dlen,
                  "Section name:",
                  ".text");

      (*callback)(args,
                  "%-*s 0x%08X (%d)",
                  dlen,
                  "Size (bytes):",
                  ExecHeader->a_text,
                  ExecHeader->a_text);

      (*callback)(args,
                  "%-*s 0x%08X (%d)",
                  dlen,
                  "File offset:",
                  N_TXTOFF(*ExecHeader),
                  N_TXTOFF(*ExecHeader));
    }
    else if (!strcasecmp(name, ".data"))
    {
      (*callback)(args,
                  "%-*s %s",
                  dlen,
                  "Section name:",
                  ".data");

      (*callback)(args,
                  "%-*s 0x%08X (%d)",
                  dlen,
                  "Size (bytes):",
                  ExecHeader->a_data,
                  ExecHeader->a_data);

      (*callback)(args,
                  "%-*s 0x%08X (%d)",
                  dlen,
                  "File offset:",
                  N_DATOFF(*ExecHeader),
                  N_DATOFF(*ExecHeader));
    }
    else if (!strcasecmp(name, ".bss"))
    {
      (*callback)(args,
                  "%-*s %s",
                  dlen,
                  "Section name:",
                  ".bss");

      (*callback)(args,
                  "%-*s 0x%08X (%d)",
                  dlen,
                  "Size (bytes):",
                  ExecHeader->a_bss,
                  ExecHeader->a_bss);
    }
    else
    {
      (*callback)(args,
                  "No section found matching: %s",
                  name);
    }

    return;
  } /* if (name) */

  (*callback)(args,
              "%-20s %-13s %-13s %-8s",
              "Section name",
              "Start",
              "End",
              "Length (bytes)");

  /*
   * Gotta love a.out :-) - only a few sections to worry about
   */
  (*callback)(args,
              "%-20s 0x%08X -> 0x%08X    0x%08X",
              ".text",
              ExecHeader->a_entry + N_TXTOFF(*ExecHeader),
              ExecHeader->a_entry + N_TXTOFF(*ExecHeader) + ExecHeader->a_text,
              ExecHeader->a_text);

  /*
   * .data always comes directly after .text
   */
  (*callback)(args,
              "%-20s 0x%08X -> 0x%08X    0x%08X",
              ".data",
              ExecHeader->a_entry + N_TXTOFF(*ExecHeader) + ExecHeader->a_text,
              ExecHeader->a_entry + N_TXTOFF(*ExecHeader) + ExecHeader->a_text +
                ExecHeader->a_data,
              ExecHeader->a_data);

  if (ExecHeader->a_bss)
  {
    (*callback)(args,
                "%-20s 0x%08X -> 0x%08X    0x%08X",
                ".bss",
                ExecHeader->a_entry + N_TXTOFF(*ExecHeader) + ExecHeader->a_text +
                  ExecHeader->a_data,
                ExecHeader->a_entry + N_TXTOFF(*ExecHeader) + ExecHeader->a_text +
                  ExecHeader->a_data + ExecHeader->a_bss,
                ExecHeader->a_bss);
  }
} /* printSectionInfoAOUT() */
