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
 * $Id: load.c,v 1.2 2004/10/09 18:22:08 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "load.h"
#include "main.h"
#include "misc.h"
#include "print.h"

#include "libDebug.h"

/*
 * libString includes
 */
#include "Strn.h"

/*
loadFile()
 Load file 'filename' by using mmap() to create a map of the file
in memory. This is the most efficient method since it also pages
for us.

Inputs: ws       - ald workspace
        filename - file to load

Return: -1 if unsuccessful
        file descriptor of 'filename' is successful

Side effects:
 - ws->MapPtr is assigned to the beginning of the mapped memory
 - ws->MappedSize is set to the size of the mapped memory
*/

int
loadFile(struct aldWorkspace *ws, char *filename)

{
  struct stat statbuf;
  int fd;
  int ret;
  char buffer[MAXLINE];
  struct offParameters offParams;
  unsigned long symcnt;

  assert(filename != 0);

  /*
   * Unload old file if there is one
   */
  if (ws->MapPtr != 0)
    unloadFile(ws);

  if ((fd = open(filename, O_RDONLY)) == (-1))
  {
    Print(ws,
          P_COMMAND,
          "Unable to open %s: %s",
          filename,
          strerror(errno));
    return (-1);
  }

  if (stat(filename, &statbuf) == (-1))
  {
    Print(ws,
          P_COMMAND,
          "stat() failed on %s: %s",
          filename,
          strerror(errno));
    close(fd);
    return (-1);
  }

  ws->MappedSize = statbuf.st_size;

  ws->MapPtr = mmap(0, ws->MappedSize, PROT_READ, MAP_PRIVATE, fd, 0);
  if (ws->MapPtr == MAP_FAILED)
  {
    Print(ws,
          P_COMMAND,
          "Unable to map memory for %s: %s",
          filename,
          strerror(errno));
    close(fd);
    return (-1);
  }

  /*
   * Attempt to identity object file format
   */

  ret = identifyOFF(ws->offWorkspace_p,
                    ws->MapPtr,
                    ws->MappedSize,
                    &offParams,
                    buffer);

  if ((ret == OFF_TYPE_UNKNOWN) || (ret < 0))
  {
    if (ret < 0)
    {
      Print(ws,
            P_ERROR,
            "%s",
            buffer);
    }

    Print(ws,
          P_COMMAND,
          "%s: Unrecognized object format, placing offset at position 0x%08X",
          filename,
          0);

    ws->virtualFileAddress = 0;
    ws->virtualEntryPoint = 0;
    ws->entryPoint = 0;
    ws->objectFileOffset = 0;
    ws->virtualObjectFileOffset = 0;
  }
  else
  {
    /*
     * We have successfully identified a file format
     */
    Print(ws,
          P_COMMAND,
          "%s: %s",
          filename,
          buffer);

    ws->virtualFileAddress = offParams.virtualFileAddress;
    ws->entryPoint = offParams.entryPoint;
    ws->virtualEntryPoint = offParams.virtualEntryPoint;

    ws->objectFileOffset = ws->entryPoint;
    ws->virtualObjectFileOffset = ws->virtualEntryPoint;

    /*
     * Load any symbols
     */
    RawPrint(ws, P_COMMAND, "Loading debugging symbols...");

    symcnt = loadSymbolsOFF(ws->offWorkspace_p);

    if (symcnt)
      Print(ws, P_COMMAND, "(%lu symbols loaded)", symcnt);
    else
      Print(ws, P_COMMAND, "(no symbols found)");

    /*
     * Go to 32 bit mode
     */
    flagsDisasm(ws->disasmWorkspace_p, DA_32BITMODE);
  }

  ws->objectFileName = Strdup(filename);
  ws->objectFileDescriptor = fd;

  return (fd);
} /* loadFile() */

/*
unloadFile()
 Unmap the previously mapped memory for the file we were debugging.

Inputs: ws - ald workspace
*/

void
unloadFile(struct aldWorkspace *ws)

{
  assert(ws->MapPtr != 0);
  assert(ws->objectFileDescriptor != (-1));

  if (munmap(ws->MapPtr, ws->MappedSize) == (-1))
  {
    Print(ws,
          P_COMMAND,
          "Error unloading file %s: %s",
          ws->objectFileName,
          strerror(errno));
  }

  close(ws->objectFileDescriptor);
  ws->objectFileDescriptor = (-1);

  if (ws->objectFileName)
    free(ws->objectFileName);

  ws->MapPtr = 0;

  awClearFileLoaded(ws);

  unloadSymbolsOFF(ws->offWorkspace_p);
} /* unloadFile() */
