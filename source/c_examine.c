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
 * $Id: c_examine.c,v 1.3 2004/09/11 05:17:16 pa33 Exp $
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "alddefs.h"
#include "defs.h"
#include "list.h"
#include "load.h"
#include "main.h"
#include "memory.h"
#include "msg.h"
#include "print.h"

#include "libDebug.h"

/*
 * libString includes
 */
#include "Strn.h"

/*
c_examine()
  Examine the debugged process' memory

Format for this command:
  examine [startaddr] [stopaddr] [-num <num>] [-size <val>]
          [-output <letter>]

Options:
  -num <value>         = number of elements to dump
  -size <value/letter> = size of each element
    Possible letter values: b (byte), w (word), h (halfword),
                            d (dword), g (giant - 8 bytes)
  -output <letter>     = output format
    Possible letter values: o (octal), d (decimal), h (hex - default)
                            b (binary)

Return: 0 upon failure
        1 upon success
*/

int
c_examine(struct aldWorkspace *ws, int ac, char **av)

{
  int cnt,
      alen;
  char *endptr;
  unsigned long startaddr, /* address to begin memory dump */
                stopaddr;  /* address to stop memory dump */
  int gotaddr;             /* did user supply start address? */
  unsigned long elnum;     /* number of elements in memory to dump */
  unsigned long elsize,    /* size of each element */
                elbytes;   /* number of bytes for all elements */
  unsigned char output;    /* output type (hex, binary, etc) */
  unsigned char *membuf;   /* where to store dumped memory */
  unsigned long numbytes;  /* number of bytes of memory to dump */
  long ndumped;            /* number of bytes actually dumped */
  unsigned long deladdr;   /* delta address (stopaddr - startaddr) */
  struct genericList *ptr;

  /*
   * Defaults: dump 64 elements, each 1 byte, in hex format
   */
  elnum = 64;
  elsize = 1;
  output = (unsigned char) 'h';
  startaddr = 0;
  stopaddr = 0;
  gotaddr = 0;

  for (cnt = 1; cnt < ac; ++cnt)
  {
    alen = strlen(av[cnt]);

    if (!Strncasecmp(av[cnt], "-num", alen))
    {
      if (++cnt >= ac)
      {
        Print(ws, P_ERROR, "No element number specified");
        return (0);
      }

      elnum = strtoul(av[cnt], &endptr, 0);
      if ((endptr == av[cnt]) || (*endptr != '\0'))
      {
        Print(ws, P_ERROR, "Invalid element number: %s", av[cnt]);
        return (0);
      }
    }
    else if (!Strncasecmp(av[cnt], "-size", alen))
    {
      if (++cnt >= ac)
      {
        Print(ws, P_ERROR, "No element size specified");
        return (0);
      }

      elsize = GetElementSize(av[cnt]);
      if (!elsize)
      {
        Print(ws, P_ERROR, "Invalid element size: %s", av[cnt]);
        return (0);
      }
    }
    else if (!Strncasecmp(av[cnt], "-output", alen))
    {
      if (++cnt >= ac)
      {
        Print(ws, P_ERROR, "No element size specified");
        return (0);
      }

      output = (unsigned char) *av[cnt];

      /*
       * We'll let OutputMemory() do any error checking on the
       * output type
       */
    }
    else
    {
      if (!gotaddr)
      {
        gotaddr = 1;
        startaddr = strtoul(av[cnt], &endptr, 0);

        if ((endptr == av[cnt]) || (*endptr != '\0'))
        {
          int ret;
          int sret;
          struct offSectionInfo secInfo;
          struct offSymbolInfo symInfo;

          /*
           * It is not a valid numerical address, but they
           * may have specified a register name wanting to
           * start the dump at the address in the register
           * so check for that before giving an error
           */
          ret = findRegisterDebug(ws->debugWorkspace_p, av[cnt]);
          if (ret != (-1))
          {
            startaddr = (unsigned long)
                         readRegisterDebug(ws->debugWorkspace_p,
                                           ret);
          }
          else
          {
            /*
             * Maybe it is a section name
             */
            sret = findSectionOFF(ws->offWorkspace_p,
                                  av[cnt],
                                  0,
                                  &secInfo);
            if (sret)
            {
              startaddr = (unsigned long) secInfo.address;
              elnum = secInfo.size;
            }
            else
            {
              /*
               * Maybe it is a symbol name
               */
              sret = findSymbolOFF(ws->offWorkspace_p,
                                   av[cnt],
                                   0,
                                   &symInfo);
              if (sret)
              {
                startaddr = (unsigned long) symInfo.address;
                elnum = symInfo.size;
              }
              else
              {
                Print(ws, P_ERROR, "Invalid address: %s", av[cnt]);
                return (0);
              }
            }
          }
        } /* if (!gotaddr) */
      }
      else
      {
        stopaddr = strtol(av[cnt], &endptr, 0);

        if ((endptr == av[cnt]) || (*endptr != '\0'))
        {
          Print(ws, P_ERROR, "Invalid address: %s", av[cnt]);
          return (0);
        }
      }
    }
  } /* for (cnt = 1; cnt < ac; ++cnt) */

  if (!gotaddr)
  {
    /*
     * If no start address was specified, the first choice is
     * the address of the next instruction about to be executed.
     * Second choice is the program's entry point, since if
     * nextInstruction is 0, the program hasn't started yet.
     */
    if (ws->nextInstruction)
      startaddr = ws->nextInstruction;
    else
      startaddr = ws->virtualEntryPoint;
  }

  membuf = 0;

  /*
   * Determine exactly how many bytes of memory we want to
   * dump
   */
  elbytes = elnum * elsize;

  if (elbytes < elnum)
  {
    /* integer overflow occurred */
    Print(ws,
          P_ERROR,
          "error: integer overflow");
    return (0);
  }

  if (stopaddr >= startaddr)
    deladdr = stopaddr - startaddr;
  else
    deladdr = 0;

  if (deladdr > elbytes)
    numbytes = deladdr;
  else
    numbytes = elbytes;

  ndumped = dumpMemoryDebug(ws->debugWorkspace_p,
                            &membuf,
                            startaddr,
                            numbytes);

  if (membuf)
  {
    /*
     * OutputMemory uses print bursts, so if the user kills
     * the burst before it completes, the following free()
     * will not be called. So add 'membuf' to the list of
     * items to be freed, in case longjmp() is called.
     * After the setjmp() statement in procCommand, the
     * 'toBeFreed' list will be freed.
     */
    ptr = insertList(&(ws->toBeFreed), (void *) membuf);

    if (ndumped > 0)
      OutputMemory(ws, membuf, startaddr, ndumped, elsize, output);

    free(membuf);

    deleteList(&(ws->toBeFreed), ptr);
  }

  if ((unsigned long) ndumped < numbytes)
  {
    Print(ws,
          P_ERROR,
          MSG_NOACCESS,
          startaddr + ndumped,
          strerror(errno));
  }

  return (1);
} /* c_examine() */
