/*
 * libDASM
 *
 * Copyright (C) 2000-2003 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: disasm.c,v 1.2 2004/09/02 00:11:59 pa33 Exp $
 *
 * This program is designed to test the libDASM library by using it
 * to disassemble a file and display the results.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "disasm.h"
#include "libDASM.h"

/*
initMain()
  Initialize our main workspace
*/

struct mainWorkspace *
initMain(unsigned int flags)

{
  struct mainWorkspace *ws;

  ws = (struct mainWorkspace *) malloc(sizeof(struct mainWorkspace));
  if (!ws)
  {
    fprintf(stderr,
            "initMain: malloc failed: %s\n",
            strerror(errno));
    return (0);
  }

  memset(ws, '\0', sizeof(struct mainWorkspace));

  ws->disasmWorkspace_p = initDisasm(flags);
  if (!ws->disasmWorkspace_p)
  {
    termMain(ws);
    return (0);
  }

  ws->circIndex = 0;
  ws->bytesNeeded = MAX_OPCODE_LEN;
  ws->offset = 0;

  return (ws);
} /* initMain() */

/*
termMain()
  Terminate main workspace
*/

void
termMain(struct mainWorkspace *ws)

{
  if (!ws)
    return;

  if (ws->disasmWorkspace_p)
    free(ws->disasmWorkspace_p);

  free(ws);
} /* termMain() */

/*
procMain()

Inputs: ws     - main workspace
        buffer - buffer of opcodes
        len    - length of buffer

Return: number of bytes disassembled
*/

int
procMain(struct mainWorkspace *ws, unsigned char *buffer, int len)

{
  register unsigned char *circInput;   /* circular input buffer */
  unsigned char input[MAX_OPCODE_LEN]; /* disassemble input buffer */
  unsigned char output[MAXLINE];       /* disassemble output buffer */
  long numBytes;                       /* number of bytes disassembled */
  int ii,                              /* looping */
      jj;
  int ret;                             /* return result */
  int circidx;                         /* index into circInput[] */
  char mcode[MAXLINE];                 /* machine code */
  int idx;                             /* index */

  ret = 0;
  circInput = ws->circInput;

  for (ii = 0; ii < len; ++ii)
  {
    circInput[ws->circIndex] = buffer[ii];

    --(ws->bytesNeeded);

    if (!ws->bytesNeeded)
    {
      /*
       * We have enough bytes in circInput[] to disassemble
       * at least one opcode. Construct our input buffer.
       */
      circidx = ws->circIndex;
      for (jj = (MAX_OPCODE_LEN - 1); jj >= 0; --jj)
      {
        input[jj] = circInput[circidx];

        /*
         * Go backwards using circular addressing
         */
        circidx = (circidx + CIRC_SIZE - 1) & (CIRC_SIZE - 1);
      }

      /*
       * Disassemble our opcode
       */
      numBytes = procDisasm(ws->disasmWorkspace_p,
                            input,
                            output,
                            ws->offset);

      if (numBytes < 0)
      {
        fprintf(stderr, "procDisasm: error: %s\n", output);
        exit(1);
      }

      if (numBytes == 0)
      {
        sprintf(mcode, "%02X", *input);
        sprintf(output, "???");

        printf("%08X %-20s %s\n",
               ws->offset,
               mcode,
               output);

        ++(ws->offset);
        ws->bytesNeeded = 1;
        ++ret;
      }
      else
      {
        idx = 0;
        for (jj = 0; jj < numBytes; ++jj)
        {
          sprintf(mcode + 2*idx, "%02X", (unsigned char) input[idx]);
          ++idx;
        }

        printf("%08X %-20s %s\n",
               ws->offset,
               mcode,
               output);

        ws->offset += numBytes;
        ws->bytesNeeded = numBytes;
        ret += (int) numBytes;
      }

    } /* if (!ws->bytesNeeded) */

    /*
     * Increase our index into circInput[] by one, accounting
     * for circular addressing
     */
    ws->circIndex = (ws->circIndex + 1) & (CIRC_SIZE - 1);
  } /* for (ii = 0; ii < len; ++ii) */

  return (ret);
} /* procMain() */

/*
flushMain()
  Flush any opcodes which have not yet been disassembled.
By the design of procMain(), a disassemble only occurs
when we have MAX_OPCODE_LEN number of opcode bytes in our
circular buffer. So if we hit an EOF in the file we
are disassembling, it is likely that we have one or more
opcodes in our circular buffer which have not been disassembled
yet, since most opcodes will be less than MAX_OPCODE_LEN
in length.
*/

int
flushMain(struct mainWorkspace *ws)

{
  int ret;
  int max;
  int circidx;
  unsigned char buffer[MAXLINE];

  circidx = ws->circIndex;

  memset(buffer, '\0', sizeof(buffer));
  ret = 0;

  max = MAX_OPCODE_LEN - ws->bytesNeeded;

  while (ret < max)
    ret += procMain(ws, buffer, ws->bytesNeeded);

  return (ret);
} /* flushMain() */

int
main(int argc, char *argv[])

{
  struct mainWorkspace *mainWorkspace_p;
  FILE *fp;
  unsigned char buf[MAX_FILE_READ];
  char *filename;
  size_t len;
  unsigned int flags;                /* disassemble flags */
  int i;                             /* looping */
  int mainRet;                       /* return from procMain() */

  filename = 0;
  flags = DA_16BITMODE;

  for (i = 1; i < argc; ++i)
  {
    if (!strcmp(argv[i], "-32"))
      flags = DA_32BITMODE;
    else
      filename = argv[i];
  }

  if (!filename)
  {
    printf("Usage: %s [-32] <filename>\n", argv[0]);
    exit(1);
  }

  fp = fopen(filename, "r");
  if (!fp)
  {
    perror("fopen");
    exit(1);
  }

  mainWorkspace_p = initMain(flags);
  if (!mainWorkspace_p)
    exit(1);

  while ((len = fread(buf, 1, MAX_FILE_READ, fp)))
  {
    if (len != MAX_FILE_READ)
    {
      /*
       * We hit an EOF with a partial buffer, so
       * zero pad the rest of buf[]
       */
      for (i = len; i < MAX_FILE_READ; ++i)
        buf[i] = '\0';
    }

    mainRet = procMain(mainWorkspace_p,
                       buf,
                       MAX_FILE_READ);
  }

  /*
   * Flush out any lingering opcodes
   */
  flushMain(mainWorkspace_p);

  termMain(mainWorkspace_p);

  fclose(fp);

  return 0;
} /* main() */
