/*
 * libDebug
 *
 * Copyright (C) 2000-2003 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: libDebug.c,v 1.4 2004/09/18 03:41:15 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "libDebug.h"

/*
initDebug()
  Initialize debug workspace
*/

struct debugWorkspace *
initDebug()

{
  struct debugWorkspace *ws;

  ws = (struct debugWorkspace *) malloc(sizeof(struct debugWorkspace));
  if (!ws)
  {
    fprintf(stderr, "initDebug: malloc failed: %s\n", strerror(errno));
    return (0);
  }

  memset(ws, '\0', sizeof(struct debugWorkspace));

  ws->pid = NOPID;
  ws->breakNumber = 1;

  ws->fpuState = (struct x86fpuInfo *) malloc(sizeof(struct x86fpuInfo));
  if (!ws->fpuState)
  {
    fprintf(stderr, "initDebug: malloc failed: %s\n", strerror(errno));
    termDebug(ws);
    return (0);
  }

  memset(ws->fpuState, '\0', sizeof(struct x86fpuInfo));

  if (!x86initRegistersDebug(ws))
  {
    fprintf(stderr, "initDebug: x86initRegisters failed\n");
    termDebug(ws);
    return (0);
  }

  return (ws);
} /* initDebug() */

/*
termDebug()
  Terminate debug workspace
*/

void
termDebug(struct debugWorkspace *ws)

{
  if (!ws)
    return;

  if (ws->path)
    free(ws->path);

  if (ws->args)
    free(ws->args);

  if (ws->argsLinear)
    free(ws->argsLinear);

  if (ws->fpuState)
    free(ws->fpuState);

  clearBreakpoints(ws);

  free(ws);
} /* termDebug() */

/*
startDebug()
  Called when a new file is loaded into memory for debugging. Set up
necessary parameters in our workspace

Inputs: ws       - workspace
        path     - path to program being debugged
        redirect - set to 1 if we want to redirect and capture
                   the input/output of our debugged program
*/

void
startDebug(struct debugWorkspace *ws, char *path, int redirect)

{
  size_t len;

  if (ws->path)
    free(ws->path);

  /*
   * Make a duplicate of path
   */

  len = strlen(path) + 1;

  ws->path = malloc(len);
  if (!ws->path)
  {
    fprintf(stderr,
            "startDebug: malloc failed: %s\n",
            strerror(errno));
    return;
  }

  memcpy(ws->path, path, len);

  if (ws->args)
    ws->args[0] = ws->path;
  else
    setArgsDebug(ws, 0);

  if (redirect)
    dbSetRedirect(ws);

  memset(ws->output, 0, sizeof(ws->output));
} /* startDebug() */

/*
endDebug()
  Called when our process terminates (or to terminate it) - cleanup

Return: none
*/

void
endDebug(struct debugWorkspace *ws)

{
  killDebug(ws);
  clearTemporaryBreakpoints(ws);

  ws->pid = NOPID;

  dbClearRunning(ws);
  dbClearHitBreakpoint(ws);

  if (dbIsRedirect(ws))
  {
    close(ws->pipes[0]);
    close(ws->pipes[1]);
  }
} /* endDebug() */

/*
getAddressDebug()
  Return the (virtual) address of the next instruction to be
executed
*/

unsigned long
getAddressDebug(struct debugWorkspace *ws)

{
  return (ws->instructionPointer);
} /* getAddressDebug() */

/*
isRunningDebug()
  Determine if a debugged process is currently running

Return: if process is running, return 1, otherwise 0
*/

int
isRunningDebug(struct debugWorkspace *ws)

{
  return (dbIsRunning(ws));
} /* isRunningDebug() */


/*
getOutputDebug()
  Return a pointer to the buffer containing data from the debugged
process' stdout or stderr writes
*/

char *
getOutputDebug(struct debugWorkspace *ws)

{
  return (ws->output);
} /* getOutputDebug() */

/*
getArgsDebug()
  Return runtime program arguments
*/

char *
getArgsDebug(struct debugWorkspace *ws)

{
  return (ws->argsLinear);
} /* getArgsDebug() */

/*
setArgsDebug()
  Set the runtime program arguments for the debugged process

Inputs: ws   - debug workspace
        args - arguments
*/

void
setArgsDebug(struct debugWorkspace *ws, char *args)

{
  int count;
  size_t len;

  if (ws->args)
  {
    free(ws->args);
    ws->args = NULL;
  }

  if (ws->argsLinear)
  {
    free(ws->argsLinear);
    ws->argsLinear = NULL;
  }

  /*
   * We cannot trust the given buffer for use with SplitArgs(),
   * since it may be a temporary variable. Also, put a '.'
   * character first to reserve room for the program's path -
   * conventionally, the program's name is put in argv[0].
   */
  if (args)
  {
    /*
     * Make a copy of args
     */

    len = strlen(args) + 1;

    ws->argsLinear = malloc(len);
    if (!ws->argsLinear)
    {
      fprintf(stderr,
              "setArgsDebug: malloc failed: %s\n",
              strerror(errno));
      return;
    }

    memcpy(ws->argsLinear, args, len);

    strcpy(ws->argbuf, ". ");
    strncpy(ws->argbuf + 2, args, sizeof(ws->argbuf) - 2);
  }
  else
    strcpy(ws->argbuf, ".");

  count = SplitArgs(ws->argbuf, &(ws->args));
  assert(count > 0);

  ws->args[0] = ws->path;
} /* setArgsDebug() */

/*
getPathDebug()
  Return the path to the program being debugged
*/

char *
getPathDebug(struct debugWorkspace *ws)

{
  return (ws->path);
} /* getPathDebug() */

/*
killDebug()
  Kill the current debugged process - this function should
only be called from endDebug() - since that function
also takes care of resetting variables
*/

int
killDebug(struct debugWorkspace *ws)

{
  return (x86killDebug(ws));
} /* killDebug() */

#if 0
/*
getAllRegistersDebug()
  Get a list of all registers and their values

Inputs: count    - modified to contain number of registers
        regindex - optional index corresponding to a specific
                   register to display

Return: pointer to array of strings containing register info
NOTE: memory is allocated for the return pointer, so it
      must be freed by the calling function
*/

char **
getAllRegistersDebug(struct debugWorkspace *ws, int *count, int regindex)

{
  return (x86getAllRegistersDebug(ws, count, regindex));
} /* getAllRegistersDebug() */

#endif /* 0 */

/*
printRegistersDebug()
  Traverse register list and call a callback function with each register's name
and value

Inputs: ws           - debug workspace
        regindex     - optional specific register index to callback
                       (in order to grab just one register)
        flags        - flags (DB_REGFL_xxx)
        callback     - callback function:
                       void *callback(char *regname, char *regvalue,
                                      char *regvalalt, void *args);
        callbackArgs - arguments to be passed to the callback function

Return: 1 if successful, 0 if not
*/

int
printRegistersDebug(struct debugWorkspace *ws, int regindex,
                    unsigned int flags, void (*callback)(),
                    void *callbackArgs)

{
  return (x86printRegistersDebug(ws,
                                 regindex,
                                 flags,
                                 callback,
                                 callbackArgs));
} /* printRegistersDebug() */

/*
stepIntoDebug()
  Single step our program by 'num' instructions, stepping
into any subroutines

Inputs: ws   - debug workspace
        num  - number of instructions to step
        data - modified to contain various data, depending
               on the return result

Return: 0 if unsuccessful
        1 if successful
        2 if program is stopped due to a signal (data will contain
        signal number)
        3 if program encounters breakpoint (data will contain
        breakpoint number)
        4 if program ends (data will contain exit status)
        5 if program outputs data and RedirectIO is set
        6 if program is not executable
        7 if program terminates due to a signal (signal num goes in data)
*/

int
stepIntoDebug(struct debugWorkspace *ws, int num, int *data)

{
  return (x86stepIntoDebug(ws, num, data));
} /* stepIntoDebug() */

/*
stepOverDebug()
  Single step our program by 'num' instructions, stepping
into any subroutines

Inputs: ws   - debug workspace
        num  - number of instructions to step
        data - modified to contain various data, depending
               on the return result

Return: 0 if unsuccessful
        1 if successful
        2 if program is stopped due to a signal (data will contain
          signal number)
        3 if program encounters breakpoint (data will contain
          breakpoint number)
        4 if program ends (data will contain exit status)
        5 if program outputs data and RedirectIO is set
        6 if program is not executable
        7 if program terminates due to a signal (signal num goes in data)
*/

int
stepOverDebug(struct debugWorkspace *ws, int num, int *data)

{
  return (x86stepOverDebug(ws, num, data));
} /* stepOverDebug() */

/*
continueDebug()
  Continue the current process from where it left off

Inputs: ws   - debug workspace
        data - modified depending on return value

Return: 0 if unsuccessful (ptrace error)
        1 if successful
        2 if signal caught (data modified to contain signal)
        3 if breakpoint encountered (breakpoint number stored in data)
        4 if program terminates normally (exit status stored in data)
        5 if program outputs data and RedirectIO is set
        6 if program is not executable
        7 if program terminates due to a signal (signal number stored in data)
*/

int
continueDebug(struct debugWorkspace *ws, int *data)

{
  return (x86continueDebug(ws, data));
} /* continueDebug() */

/*
findRegisterDebug()
  Find register matching the given string

Inputs: ws   - debug workspace
        name - register name

Return: an internal array index matching the given register -
        this array index has no significance to an outside
        program, but it will have to be provided to SetRegister()
        should an outside routine want to change a register value.
        -1 is returned if no register matching 'name' is found
*/

int
findRegisterDebug(struct debugWorkspace *ws, char *name)

{
  return (x86findRegisterDebug(ws, name));
} /* findRegisterDebug() */

/*
setRegisterDebug()
  Set a register to a given value

Inputs: ws       - debug workspace
        regindex - index of register
        value    - new value in ascii format

Return: 1 if successful
        -1 if ptrace error occurs
        -2 if an invalid value is given
*/

int
setRegisterDebug(struct debugWorkspace *ws, int regindex, char *value)

{
  return (x86setRegisterDebug(ws, regindex, value));
} /* setRegisterDebug() */

/*
readRegisterDebug()
  Get the contents of a register

Inputs: ws       - debug workspace
        regindex - index of register

Return: contents of register
*/

long
readRegisterDebug(struct debugWorkspace *ws, int regindex)

{
  return (x86readIntRegisterDebug(ws, regindex));
} /* readRegisterDebug() */

/*
getFlagsDebug()
  Return a human readable listing of the flags register settings

Inputs: wsa   - debug workspace
        flags - where to store human readable flags

Return: 1 if successful
        0 if not
*/

int
getFlagsDebug(struct debugWorkspace *ws, char *flags)

{
  return (x86getFlagsDebug(ws, flags));
} /* getFlagsDebug() */

/*
dumpMemoryDebug()
  Dump memory contents of debugged process

Inputs: ws    - debug workspace
        buf   - buffer to store memory bytes in
        start - address to start dump
        bytes - number of bytes to dump

Return: number of bytes dumped - if this value is less than 'bytes',
        an error occurred and errno should be set appropriately

Side effects: upon success, memory is allocated for 'buf', so it
              must be freed by the calling function
*/

long
dumpMemoryDebug(struct debugWorkspace *ws, unsigned char **buf,
                unsigned long start, unsigned long bytes)

{
  return (x86dumpMemoryDebug(ws, buf, start, bytes));
} /* dumpMemoryDebug() */

/*
setMemoryDebug()
  Set the contents of memory address 'address' to 'value'

Inputs: ws      - debug workspace
        address - memory address
        value   - value to set

Return: 0 if unsuccessful (usually permission denied)
        number of bytes written to memory if successful
*/

int
setMemoryDebug(struct debugWorkspace *ws, unsigned long address,
               unsigned long value)

{
  return (x86setMemoryDebug(ws, address, value));
} /* setMemoryDebug() */

/*
attachDebug()
  Attach to a currently running process

Inputs: ws  - debug workspace
        pid - process id

Return: 1 if successful, 0 if not
*/

int
attachDebug(struct debugWorkspace *ws, int pid)

{
  return (x86attachDebug(ws, pid));
} /* attachDebug() */

/*
detachDebug()
  Detach from current process

Inputs: ws - debug workspace

Return: -1 if not attached to a process
        0 if not
        pid of detached process if successful
*/

int
detachDebug(struct debugWorkspace *ws)

{
  return (x86detachDebug(ws));
} /* detachDebug() */
