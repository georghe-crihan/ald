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
 * $Id: memory.c,v 1.3 2004/07/21 16:36:06 pa33 Exp $
 */

#include <stdlib.h>
#include <assert.h>

#include "alddefs.h"
#include "defs.h"
#include "main.h"
#include "memory.h"
#include "print.h"

struct MemFormat OutputFormats[] = {
  { 'x', "hex", "%02X ", 16, 2 },         /* MF_1HEX */
  { 'x', "hex", "%04X ", 8, 4 },         /* MF_2HEX */
  { 'x', "hex", "%08X ", 4, 8 },          /* MF_4HEX */
  { 'x', "hex", "%016X ", 16, 16 },       /* MF_8HEX */
  { 'o', "octal", "%03o ", 8, 3 },       /* MF_1OCTAL */
  { 'o', "octal", "%06o ", 6, 6 },       /* MF_2OCTAL */
  { 'o', "octal", "%011o ", 4, 11 },     /* MF_4OCTAL */
  { 'd', "decimal", "%03u ", 10, 3 },    /* MF_1DECIMAL */
  { 'd', "decimal", "%05u ", 8, 5 },     /* MF_2DECIMAL */
  { 'd', "decimal", "%010u ", 4, 10 },   /* MF_4DECIMAL */

  { 0, 0, 0, 0, 0 }
};

static struct MemFormat *GetOutputFormat(unsigned char output,
                                         long elsize);
static unsigned long GetMemoryValue(unsigned char *buf, long size,
                                    int *err);

/*
GetOutputFormat()
  Look up a suitable output format for the given output arg.

Inputs: output - character representing a base output
        elsize - size of each output element

Return: pointer to index of OutputFormats[] corresponding to 'output'.
        If 'output' does not match any known formats, default to
        hexadecimal.
*/

static struct MemFormat *
GetOutputFormat(unsigned char output, long elsize)

{
  unsigned char idx = MF_1HEX;

  if (output == 'o')
  {
    if (elsize == 1)
      idx = MF_1OCTAL;
    else if (elsize == 2)
      idx = MF_2OCTAL;
    else if (elsize == 4)
      idx = MF_4OCTAL;
  }
  else if (output == 'd')
  {
    if (elsize == 1)
      idx = MF_1DECIMAL;
    else if (elsize == 2)
      idx = MF_2DECIMAL;
    else if (elsize == 4)
      idx = MF_4DECIMAL;
  }
  else
  {
    if (elsize == 1)
      idx = MF_1HEX;
    else if (elsize == 2)
      idx = MF_2HEX;
    else if (elsize == 4)
      idx = MF_4HEX;
    else if (elsize == 8)
      idx = MF_8HEX;
  }

  return (&OutputFormats[idx]);
} /* GetOutputFormat() */

/*
GetElementSize()
  This routine calculates the numerical size of each element
being examined in memory as a result of the "examine -size X"
command.

Inputs: str - string containing size

Return: positive value corresponding to the number of bytes in 'str'.
        If str contains a positive, non-zero value, that is converted
        to an integer and returned. If it contains a special letter,
        that is converted to an integer according to the following
        rules.
        If str contains a negative number or an invalid letter,
        return 0.

letter         value      meaning
b              1          byte
h              ? / 2      halfword
w              ?          word
d              ? * 2      doubleword
g              8          giant (8 bytes)

? - This value depends on the size of the machine word for the
    architecture we are running on
*/

unsigned long
GetElementSize(char *str)

{
  unsigned long ret;
  char *endptr;
  unsigned char c;

  assert(str != 0);

  ret = strtoul(str, &endptr, 0);
  if ((endptr != str) && (*endptr == '\0'))
  {
    /*
     * It is a valid number
     */
    if (ret > 0)
      return (ret);
    else
      return (0); /* negative number - no good */
  }

  c = (unsigned char) *str;
  switch (c)
  {
    /*
     * One byte
     */
    case 'b':
    case 'B':
    {
      return (1);
      /*NOTREACHED*/
      break;
    }

    /*
     * One word
     */
    case 'w':
    case 'W':
    {
      return (WORDSIZE);
      /*NOTREACHED*/
      break;
    }

    /*
     * Half a word
     */
    case 'h':
    case 'H':
    {
      return (HALFWORD);
      /*NOTREACHED*/
      break;
    }

    /*
     * Double word
     */
    case 'd':
    case 'D':
    {
      return (DWORD);
      /*NOTREACHED*/
      break;
    }

    /*
     * Giant (8 bytes)
     */
    case 'g':
    case 'G':
    {
      return (8);
      /*NOTREACHED*/
      break;
    }

    /*
     * Unknown size
     */
    default:
    {
      return (0);
      /*NOTREACHED*/
      break;
    }
  } /* switch (c) */

  /*NOTREACHED*/
  return (0);
} /* GetElementSize() */

/*
GetMemoryValue()
  Determine the numerical value of the next element in memory

Inputs: buf  - buffer containing next element
        size - size (in bytes) of next element

Outputs: err - set to 1 if something goes wrong

Return: value of next element of memory
*/

static unsigned long
GetMemoryValue(unsigned char *buf, long size, int *err)

{
  unsigned long ret = 0;
  int length = 0;

  /*
   * Thank god for little endian :-)
   */

  if (size == 1)
  {
    ret = (unsigned char) buf[length++];
  }
  else if (size == 2)
  {
    ret = (unsigned char) buf[length++];
    ret += (unsigned char) buf[length++] * 256;
  }
  else if (size == 4)
  {
    ret = (unsigned char) buf[length++];
    ret += (unsigned char) buf[length++] * 256;
    ret += (unsigned char) buf[length++] * 65536;
    ret += (unsigned char) buf[length++] * 16777216;
  }
  else
    *err = 1;

  return (ret);
} /* GetMemoryValue() */

/*
OutputMemory()
  Output a memory dump in a readable format

Inputs: ws     - main workspace
        buf    - buffer containing bytes of memory
        start  - address of first byte in memory
        bytes  - number of bytes in 'buf'
        size   - size of each element in 'buf'
        output - output format (hex, dec, etc)
*/

void
OutputMemory(struct aldWorkspace *ws, unsigned char *buf,
             unsigned long start, long bytes, long size,
             unsigned char output)

{
  unsigned char *bufptr;
  long element;        /* current element we are printing */
  unsigned char *end;
  struct MemFormat *fptr;
  unsigned long addr;  /* current address we are printing */
  char abuf[MAXLINE];  /* ascii buffer */
  char *aptr;
  int ecnt;            /* number of elements we have printed so far */
  int extranl;
  int ii,              /* looping */
      err;             /* has an error occurred? */
#if 0
  int ascii;           /* set to 1 if we should print ascii */
#endif

  fptr = GetOutputFormat(output, size);
  assert(fptr != 0);

  end = buf + bytes;
  bufptr = buf;

  startPrintBurst(ws->printWorkspace_p);

  Print(ws,
        P_MEMORY,
        "Dumping %ld bytes of memory starting at 0x%08lX in %s",
        bytes,
        start,
        fptr->desc);

  ecnt = 0;
  addr = start;
  aptr = abuf;
  extranl = 1;

  /*
   * There is little point in printing ascii characters if our
   * elements are more than 1 byte.
   */
#if 0
  if (size != 1)
    ascii = 0;
  else
    ascii = 1;
#endif

  RawPrint(ws, P_MEMORY, "%08lX:  ", start);

  while (bufptr < end)
  {
    err = 0;
    element = GetMemoryValue(bufptr, size, &err);
    if (err)
    {
      /*
       * Should not happen
       */
      Print(ws,
            P_ERROR,
            "OutputMemory: currently only sizes of 1, 2, or 4 bytes are supported");
      endPrintBurst(ws->printWorkspace_p);
      return;
    }

    /*
     * Print the current element with it's correct formatting
     */
    RawPrint(ws, P_MEMORY, fptr->fmt, element);

    addr += size;

#if 0
    if (ascii)
    {
#endif
      /*
       * Keep our ascii buffer updated, as well as advance bufptr
       * by 'size' bytes
       */
      for (ii = 0; ii < size; ++ii)
        *aptr++ = *bufptr++;
#if 0
    }
    else
      bufptr += size;
#endif

    if ((++ecnt == fptr->epl) || (bufptr >= end))
    {
    #if 0
      if (ascii)
      {
    #endif
        if (bufptr >= end)
        {
          /*
           * We have partially completed the last line - fill the
           * rest up with spaces so we can line our ascii printout
           * up correctly.
           */
          RawPrint(ws,
                   P_MEMORY,
                   "%*s",
                   (fptr->epl - ecnt) * (fptr->cpe + 1),
                   "");
        }

        RawPrint(ws, P_MEMORY, "   ");

        /*
         * Output the ascii equivalent of the bytes we just
         * printed
         */
        aptr = abuf;
        /*for (ii = 0; ii < ecnt; ++ii)*/
        for (ii = 0; ii < (ecnt * size); ++ii)
        {
          if ((*(aptr + ii) >= ' ') && (*(aptr + ii) < 127))
            RawPrint(ws, P_MEMORY, "%c", (unsigned char) *(aptr + ii));
          else
            RawPrint(ws, P_MEMORY, "%c", '.');
        }
    #if 0
      } /* if (ascii) */
    #endif

      /*
       * We have reached the last element in the line so output
       * a newline character and continue
       */
      RawPrint(ws, P_MEMORY, "\n");
      if (bufptr < end)
        RawPrint(ws, P_MEMORY, "%08lX:  ", addr);
      else
        extranl = 0;

      ecnt = 0;
    }
  }

  if (extranl)
    RawPrint(ws, P_MEMORY, "\n");

  endPrintBurst(ws->printWorkspace_p);
} /* OutputMemory() */
