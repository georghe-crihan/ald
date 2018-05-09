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
 * $Id: id.c,v 1.1.1.1 2004/04/26 00:40:33 pa33 Exp $
 *
 * This program tests the libOFF routines by identifying
 * an object file and printing out various information about
 * it.
 *
 * Usage: ./id <filename>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdarg.h>

#include "libOFF.h"

void
myPrint(void *cargs, const char *format, ...)

{
  va_list args;

  va_start(args, format);

  vprintf(format, args);
  printf("\n");

  va_end(args);
} /* myPrint() */

int
main(int argc, char *argv[])

{
  struct offWorkspace *mainWorkspace_p;
  struct offParameters offParams;
  char *filename;
  struct stat statbuf;
  int fd;
  size_t filesize;
  void *mapPtr;
  char buf[2048];
  int ret;

  if (argc > 1)
    filename = argv[1];
  else
  {
    fprintf(stderr, "Usage: %s <file>\n", argv[0]);
    exit(1);
  }

  if (stat(filename, &statbuf) == (-1))
  {
    fprintf(stderr,
            "stat() failed on %s: %s\n",
            filename,
            strerror(errno));
    exit(1);
  }

  filesize = statbuf.st_size;

  if ((fd = open(filename, O_RDONLY)) == (-1))
  {
    fprintf(stderr,
            "Unable to open %s: %s\n",
            filename,
            strerror(errno));
    exit(1);
  }

  /*
   * Map the file into memory
   */
  mapPtr = mmap(0, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
  if (mapPtr == MAP_FAILED)
  {
    fprintf(stderr,
            "Unable to map memory for %s: %s\n",
            filename,
            strerror(errno));
    close(fd);
    exit(1);
  }

  mainWorkspace_p = initOFF();
  if (!mainWorkspace_p)
    exit(1);

  ret = identifyOFF(mainWorkspace_p,
                    mapPtr,
                    filesize,
                    &offParams,
                    buf);

  if (ret < 0)
  {
    fprintf(stderr,
            "%s\n",
            buf);
    exit(1);
  }

  if (ret == OFF_TYPE_UNKNOWN)
  {
    printf("%s: unknown file format\n", filename);
    exit(1);
  }

  printf("%s: %s\n", filename, buf);

  printf("\n*** HEADER INFORMATION ***\n\n");
  printHeaderOFF(mainWorkspace_p, &myPrint, 0);

  printf("\n*** SECTION INFORMATION ***\n\n");
  printSectionInfoOFF(mainWorkspace_p, 0, &myPrint, 0);

  printf("\n*** .DATA ***\n\n");
  printSectionInfoOFF(mainWorkspace_p, ".data", &myPrint, 0);

  printf("\n*** .TEXT ***\n\n");
  printSectionInfoOFF(mainWorkspace_p, ".text", &myPrint, 0);

  printf("\n*** .SHSTRTAB ***\n\n");
  printSectionInfoOFF(mainWorkspace_p, ".shstrtab", &myPrint, 0);

  printf("\n*** .REL.PLT ***\n\n");
  printSectionInfoOFF(mainWorkspace_p, ".rel.plt", &myPrint, 0);

  loadSymbolsOFF(mainWorkspace_p);

  printf("\n*** SYMBOLS ***\n\n");
  printSymbolsOFF(mainWorkspace_p, 0, &myPrint, 0);

  printf("\n*** SYMBOL myPrint ***\n\n");
  printSymbolsOFF(mainWorkspace_p, "myPrint", &myPrint, 0);

  termOFF(mainWorkspace_p);

  return (0);
} /* main() */
