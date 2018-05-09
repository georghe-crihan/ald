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
 * $Id: c_disassemble.c,v 1.2 2004/09/11 05:17:16 pa33 Exp $
 */

#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "alddefs.h"
#include "defs.h"
#include "disassemble.h"
#include "load.h"
#include "main.h"
#include "msg.h"
#include "print.h"

#include "libDebug.h"
#include "libOFF.h"

/*
 * libString includes
 */
#include "Strn.h"

static void ResetDisassemblyPosition(struct aldWorkspace *ws);

/*
c_disassemble()
 Disassemble the current file

Format for this command:
  disassemble [start [stop]] [-num <number>] [-section <name>]

Return: 0 upon failure
        1 upon success
*/

int
c_disassemble(struct aldWorkspace *ws, int ac, char **av)

{
  unsigned char *data;  /* data to disassemble */
  unsigned char *membuf;
  long insnum,          /* number of instructions to disassemble */
       inscnt;          /* number of instructions disassembled so far */
  char *endptr;
  long length;
  int cnt,
      alen;
  unsigned int start,
               end;
  unsigned int address; /* address of instruction to be disassembled */
  char *section;        /* are we disassembling a specific section? */
  long ndumped,         /* number of bytes dumped */
       numbytes;        /* total bytes */
  unsigned char spill[MAX_OPCODE_LEN + 1];
  int gotstart;         /* did we get a starting address? */
  int sret;             /* return result from findSectionOFF() */
  struct offSectionInfo secInfo;

  start = end = 0;
  gotstart = 0;
  section = 0;
  insnum = 0;
  ndumped = numbytes = 0;

  for (cnt = 1; cnt < ac; ++cnt)
  {
    alen = strlen(av[cnt]);
    if (!Strncasecmp(av[cnt], "-section", alen))
    {
      if (++cnt >= ac)
      {
        Print(ws, P_COMMAND, "No section name specified");
        return (0);
      }

      /*
       * Check if they already specified a starting address
       */
      if (start)
        continue;

      /*
       * Attempt to locate section by name
       */
      sret = findSectionOFF(ws->offWorkspace_p,
                            av[cnt],
                            0,
                            &secInfo);
      if (!sret)
      {
        Print(ws, P_COMMAND, "No such section: %s", av[cnt]);
        return (0);
      }

      start = secInfo.address;
      end = secInfo.address + secInfo.size;
      section = secInfo.name;
    }
    else if (!Strncasecmp(av[cnt], "-num", alen))
    {
      if (++cnt >= ac)
      {
        Print(ws, P_COMMAND, "No instruction count specified");
        return (0);
      }

      insnum = strtol(av[cnt], &endptr, 0);
      if ((endptr == av[cnt]) || (*endptr != '\0'))
      {
        Print(ws, P_COMMAND, MSG_INVNUM, av[cnt]);
        return (0);
      }
    }
    else
    {
      /*
       * It must be the starting or ending address
       */
      if (!start)
      {
        start = strtoul(av[cnt], &endptr, 0);
        gotstart = 1;
      }
      else if (!end)
        end = strtoul(av[cnt], &endptr, 0);

      if ((endptr == av[cnt]) || (*endptr != '\0'))
      {
        Print(ws, P_COMMAND, MSG_INVNUM, av[cnt]);
        return (0);
      }

      /*
       * Start/End addresses take priority over -section
       */
      section = 0;
    }
  }

  if (section)
  {
    /*
     * We are disassembling a specific section - set
     * ObjectFileOffset to the correct position.
     */
    ws->virtualObjectFileOffset = start;
    ws->objectFileOffset = start - ws->virtualFileAddress;

    Print(ws, P_COMMAND, "Disassembling section %s (0x%08X - 0x%08X)",
      section,
      start,
      end);
  } /* if (section) */

  membuf = 0;
  if (gotstart)
  {
    if (!end)
    {
      if (!insnum)
      {
        /*
         * They gave a starting memory address, but did not say when
         * to stop, so default to 15 instructions
         */
        insnum = 15;
      }

      /*
       * 150 bytes should be sufficient for 15 instructions
       */
      end = start + 150;
    }

    numbytes = end - start;
    if (numbytes < 0)
    {
      Print(ws, P_COMMAND, "Ending address is lower than starting address");
      return (0);
    }

    /*
     * Add fifteen to account for the very last instruction - in case
     * it starts at location 'end'
     */
    numbytes += 15;

    ndumped = dumpMemoryDebug(ws->debugWorkspace_p,
                              &membuf,
                              start,
                              numbytes);

    if (!ndumped)
    {
      Print(ws,
            P_COMMAND,
            MSG_NOACCESS,
            start,
            strerror(errno));

      if (membuf)
        free(membuf);

      return (0);
    }

    /*
     * In case we couldn't access all the memory we tried to dump,
     * set 'end' correctly.
     */
    if (ndumped < numbytes)
      end = start + ndumped;

    data = membuf;
    address = start;
  } /* if (gotstart) */
  else
  {
    /*
     * We are using file offsets rather than memory locations
     */

    if (ws->objectFileOffset >= ws->MappedSize)
      ResetDisassemblyPosition(ws);

    data = (unsigned char *) ws->MapPtr;
    data += ws->objectFileOffset;
    address = ws->virtualObjectFileOffset;
  }

  inscnt = 0;

  startPrintBurst(ws->printWorkspace_p);

  /*
   * There are many conditions which could cause the loop to
   * stop, so I'm using an infinite loop with a bunch of 'break'
   * checks.
   */
  while (1)
  {
    /*
     * stop if we reach the instruction limit
     */
    if (insnum && (inscnt++ >= insnum))
      break;

    /*
     * stop if we hit the end of the address range we are
     * disassembling
     */
    if (gotstart)
    {
      if (end && (address > end))
        break;
    }
    else
    {
      /*
       * stop if we go past the end of the file
       */
      if (ws->objectFileOffset >= ws->MappedSize)
        break;
      else
      {
        /*
         * Check if we are nearing the end of the file - if so,
         * use a separate buffer rather than MapPtr, because
         * if our disassembling routine screws up, it may try to
         * read a byte or two past the end of MapPtr, causing
         * a crash.
         */
        if ((ws->objectFileOffset + MAX_OPCODE_LEN) >=
            ws->MappedSize)
        {
          unsigned int ii;

          cnt = 0;
          memset((void *) spill, 0, sizeof(spill));

          for (ii = ws->objectFileOffset; ii < ws->MappedSize; ++ii)
            spill[cnt++] = (unsigned char) *((unsigned char *) ws->MapPtr + ii);

          data = spill;
        }
      }
    }

    /*
     * stop if we hit the end of the section we are disassembling
     */
    if (section && (address >= end))
      break;

    /*
     * disassemble the next instruction
     */
    length = Disassemble(ws,
                         data,
                         address,
                         P_DISASSEMBLY);

    assert(length != 0);

    if (length > 0)
    {
      data += length;
      address += length;

      if (!membuf)
      {
        ws->virtualObjectFileOffset += length;
        ws->objectFileOffset += length;
      }
    }
    else
      break; /* something went wrong */
  } /* while (1) */

  endPrintBurst(ws->printWorkspace_p);

  if (membuf)
  {
    free(membuf);
    if (ndumped < numbytes)
    {
      Print(ws,
            P_COMMAND,
            MSG_NOACCESS,
            start + ndumped,
            strerror(errno));
    }
  }

  return (1);
} /* c_disassemble() */

/*
ResetDisassemblyPosition()
  Called when we disassemble the last instruction in the file -
reset the offsets and clear the disassembly window
*/

static void
ResetDisassemblyPosition(struct aldWorkspace *ws)

{
  Print(ws,
        P_COMMAND,
        "End of file reached, repositioning offset to 0x%08x",
        ws->virtualEntryPoint);

  ws->virtualObjectFileOffset = ws->virtualEntryPoint;
  ws->objectFileOffset = ws->entryPoint;
} /* ResetDisassemblyPosition() */
