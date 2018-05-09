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
 * $Id: asm.c,v 1.1.1.1 2004/04/26 00:40:23 pa33 Exp $
 *
 * This program is designed to test the libDASM library by using it
 * to assemble a file and display the results.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "libDASM.h"

int
main(int argc, char *argv[])

{
  FILE *infp,
       *outfp;
  char *input,
       *output;
  char buffer[MAXLINE];
  unsigned char outbuf[MAXLINE];
  struct dasmWorkspace *ws;
  int aret;
  char *tmp;
  int linenum;

  input = 0;
  output = 0;

  if (argc > 1)
    input = argv[1];
  if (argc > 2)
    output = argv[2];

  if (!input || !output)
  {
    fprintf(stderr, "Usage: %s <input> <output>\n", argv[0]);
    exit(1);
  }

  infp = fopen(input, "r");
  outfp = fopen(output, "w");
  if (!infp || !outfp)
  {
    perror("fopen");
    exit(1);
  }

  ws = initDASM(DA_16BITMODE);
  if (!ws)
  {
    fclose(infp);
    fclose(outfp);
    exit(1);
  }

  linenum = 1;

  while (fgets(buffer, MAXLINE, infp))
  {
    if (*buffer == '#')
      continue;

    if ((tmp = strchr(buffer, '\n')))
      *tmp = '\0';

    aret = assembleDASM(ws, buffer, outbuf);
    if (aret < 0)
    {
      /* Error */
      fprintf(stderr,
              "error:%d: %s\n",
              linenum,
              (char *) outbuf);
    }

    if (aret > 0)
      fwrite(outbuf, sizeof(unsigned char), aret, outfp);

    ++linenum;
  }

  fclose(infp);
  fclose(outfp);

  termDASM(ws);

  return (0);
} /* main() */
