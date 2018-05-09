/*
 * libDebug
 *
 * Copyright (C) 2000 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: trace-x86.c,v 1.6 2004/10/09 17:34:15 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/*
 * Top-level includes
 */
#include "args.h"
#include "break.h"
#include "libDebug.h"

static int x86GetDebugProcessStatus(struct debugWorkspace *ws,
                                    int ptfunc, int waitval,
                                    int *data);
static int x86DoSingleStep(struct debugWorkspace *ws, int *data);
static int x86DoContinue(struct debugWorkspace *ws, int *data);

/*
x86execDebug()
  Start execution of the debugged process

Inputs: ws - debug workspace

Return: 2 if file is not executable
        1 if successful
        0 if not

Side effects: DebugPid is assigned to the pid of the traced
              process
*/

int
x86execDebug(struct debugWorkspace *ws)

{
  pid_t pid;
  int waitval;
  int err;

  assert(ws->path != 0);

  if (dbIsRedirect(ws))
  {
    if (pipe(ws->pipes) == (-1))
      return (0);
  }

  pid = fork();
  if (pid == (-1))
  {
    if (dbIsRedirect(ws))
    {
      close(ws->pipes[0]);
      close(ws->pipes[1]);
    }

    return (0);
  }
  else if (pid == 0)
  {
    /*
     * Child: allow parent to trace us
     */
    if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0)
      exit(0);

    assert(ws->args && ws->args[0]);

    if (dbIsRedirect(ws))
    {
      /*
       * Redirect child's stdout and stderr to the parent's pipe
       */
      dup2(ws->pipes[1], 1);
      dup2(ws->pipes[1], 2);

      /*
       * Redirect child's stdin to come from parent's pipe
       */
      /* dup2(ws->pipes[1], 0); */

      /*
       * Close file descriptors
       */
      close(ws->pipes[0]);
      close(ws->pipes[1]);
    }

#if 0
    if (ws->args)
    {
      printf("arg1 ==== %s\n", ws->args[1]);
    }
#endif

    execv(ws->path, ws->args);

    /*
     * If we get here the execv() returned -1 and it is most likely
     * an ENOEXEC - exiting now should alert the parent process that
     * something went wrong
     */

    exit(0);
  }
  else
  {
    /*
     * Parent process
     */

    ws->pid = pid;

    /*
     * wait for child to stop (execv)
     */
    wait(&waitval);

    /*
     * Set the instruction pointer to the program's entry point
     */
    err = 0;
    ws->instructionPointer = x86getCurrentInstruction(ws, &err);
    if (err)
    {
      /*
       * The most likely cause of this is that the file is not
       * executable
       */
      ws->pid = NOPID;
      return (2);
    }

    dbSetRunning(ws);
  }

  return (1);
} /* x86execDebug() */

/*
x86GetDebugProcessStatus()

Inputs: ws      - debug workspace
        ptfunc  - ptrace flag (PT_STEP or PT_CONTINUE)
        waitval - value containing process status
        data    - modified to contain data depending on process
                  status

Return: 0 if something goes wrong
        1 if everything is successful
        2 if program stops due to a signal (signal num goes in data)
        3 if program encounters a breakpoint (brk pt num goes in data)
        4 if program terminates normally (exit status goes in data)
        5 if program writes to stdout or stderr and we are
          redirecting output - the calling function can read the
          output using GetDebugOutput()
        6 (do not use)
        7 if program terminates due to a signal (signal number goes in data)
*/

static int
x86GetDebugProcessStatus(struct debugWorkspace *ws, int ptfunc,
                         int waitval, int *data)

{
  int sig;

  if (WIFEXITED(waitval))
  {
    /*
     * Process exited normally
     */
    endDebug(ws);

    *data = WEXITSTATUS(waitval);

    /*
     * When a program exits, it sends two signals to the parent -
     * one for the exit status and the other is a SIGCHLD, so
     * make sure we catch the second.
     */
    wait(&waitval);

    return (4);
  }
  else if (WIFSTOPPED(waitval))
  {
    sig = WSTOPSIG(waitval);

    if (sig == SIGTRAP)
    {
      unsigned long addr;
      struct Breakpoint *bptr;

      /*
       * InstructionPointer should be set appropriately by the
       * calling function
       */
      addr = ws->instructionPointer;

      if (ptfunc == PT_STEP)
      {
        /*
         * A SIGTRAP is generated after every singlestep call
         * so check before declaring it a user-defined breakpoint
         */
        if ((bptr = findBreakpoint(ws, addr)))
        {
          if (bptr->flags & BK_STEPOVER)
            printf("HIT A STEP OVER BRKPT\n");

          *data = bptr->number;

          if (bptr->ignorecnt > 0)
          {
            /*
             * Ignore this breakpoint for now and continue
             * running the process
             */
            --bptr->ignorecnt;
            return (1);
          }

          /*
           * Check if breakpoint should be deleted
           */
          checkBreakpoint(ws, bptr);

          dbSetHitBreakpoint(ws);

          return (3);
        }

        /*
         * If we get here, the SIGTRAP is the normal response
         * after the cpu set the trap flag for singlestepping
         */
      } /* if (ptfunc == PT_STEP) */
      else if (ptfunc == PT_CONTINUE)
      {
        /*
         * We stopped exactly one byte after the breakpoint
         * instruction - go back one
         */
        --addr;

        bptr = findBreakpoint(ws, addr);
        if (!bptr)
        {
          /*
           * It appears to be a SIGTRAP which we did not set -
           * this is rare, but possible.
           */
          *data = sig;

          /*
           * Do not pass this signal to the program on the next
           * ptrace since it will cause the program to terminate
           */
          /*ws->lastSignal = sig;*/

          return (2);
        }

        /*
         * Set eip to the real address
         */
        x86setCurrentInstruction(ws, addr);

        if (bptr->ignorecnt > 0)
        {
          /*
           * Ignore this breakpoint for now and continue
           * running the process
           */
          --bptr->ignorecnt;
          return (1);
        }

        if (bptr->flags & BK_STEPOVER)
          *data = 0;
        else
          *data = bptr->number;

        /*
         * Check to see if this breakpoint should be deleted
         */
        checkBreakpoint(ws, bptr);

        dbSetHitBreakpoint(ws);

        return (3);
      } /* if (ptfunc == PT_CONTINUE) */
    } /* if (sig == SIGTRAP) */
    else
    {
      *data = sig;

      /*
       * If we received a SIGINT, do not pass it to the process the
       * next time we continue ptracing, because it was probably
       * caused by the user debugging the process
       */
      if (sig != SIGINT)
        ws->lastSignal = sig;

      return (2);
    }
  } /* else if (WIFSTOPPED(waitval)) */
  else if (WIFSIGNALED(waitval))
  {
    /*
     * Program terminated due to a signal
     */
    *data = WTERMSIG(waitval);
    return (7);
  }

  /*
   * Everything is normal
   */
  return (1);
} /* x86GetDebugProcessStatus() */

/*
x86DoSingleStep()
  Singlestep one instruction in the process being debugged

Inputs: ws   - debug workspace
        data - modified to contain info depending on the return
               result

Return: 0 if something goes wrong
        1 if everything is successful
        2 if program stops due to a signal (signal num goes in data)
        3 if program encounters a breakpoint (brk pt num goes in data)
        4 if program terminates normally (exit status goes in data)
        5 if program writes to stdout or stderr and we are
          redirecting output - the calling function can read the
          output using GetDebugOutput()
*/

static int
x86DoSingleStep(struct debugWorkspace *ws, int *data)

{
  int waitval;
  int err;

  assert(ws->pid != NOPID);

  if (ptrace(PT_STEP, ws->pid, CONTADDR, ws->lastSignal) != 0)
    return (0); /* something went wrong */

  /*
   * Clear the last signal
   */
  ws->lastSignal = 0;

  /*
   * Wait for child to stop
   */
  wait(&waitval);

  err = 0;
  ws->instructionPointer = x86getCurrentInstruction(ws, &err);

  return (x86GetDebugProcessStatus(ws, PT_STEP, waitval, data));
} /* x86DoSingleStep() */

/*
x86DoContinue()
  Continue the process being debugged

Inputs: ws   - debug workspace
        data - modified to contain info depending on the return
               result

Return: 0 if something goes wrong
        1 if everything is successful
        2 if program stops due to a signal (signal num goes in data)
        3 if program encounters a breakpoint (brk pt num goes in data)
        4 if program terminates normally (exit status goes in data)
        5 if program writes to stdout or stderr and we are
          redirecting output - the calling function can read the
          output using GetDebugOutput()
        6 (don't use)
        7 if program terminates due to a signal (signal num goes in data)

Special note about breakpoints:
  If this function is invoked from x86SingleStepOver(), it is
possible that we will run into a temporary breakpoint marked
with BK_STEPOVER. Since this breakpoint was set by x86SingleStepOver()
and not by the user, it does not have a legitimate breakpoint number,
and so the special value of 0 will be placed into 'data' indicating
to x86SingleStepOver() that it's temporary breakpoint was reached.
*/

static int
x86DoContinue(struct debugWorkspace *ws, int *data)

{
  int waitval;
  int ret;
  int err;
  pid_t wret;

  assert(ws->pid != NOPID);

  if (dbHitBreakpoint(ws))
  {
    dbClearHitBreakpoint(ws);

    /*
     * We just hit a breakpoint on the previous ptrace() call,
     * and the user wants to continue from the break address.
     * We will singlestep past the breakpoint address, then
     * re-enable breakpoints and continue normally
     */
    ret = x86DoSingleStep(ws, data);
    if (ret != 1)
      return (ret); /* something stopped the process */
  }

  /*
   * An infinite loop is needed to handle cases where breakpoints
   * have an ignore count - we'll want to continue the process
   * without notifying the user that the breakpoint was hit.
   */
  while (1)
  {
    /*
     * Enable all breakpoints
     */
    enableBreakpoints(ws);

    /*fprintf(stderr, "lastsig = %d\n", ws->lastSignal);*/
    if (ptrace(PT_CONTINUE, ws->pid, CONTADDR, ws->lastSignal) != 0)
      return (0); /* something went wrong */

    /*
     * Wait for child to stop
     */
    wret = wait(&waitval);
    /*fprintf(stderr, "wret = %d\n", wret);*/

    /*
     * Disable all breakpoints
     */
    disableBreakpoints(ws);

    /*
     * Clear last signal
     */
    ws->lastSignal = 0;

    err = 0;
    ws->instructionPointer = x86getCurrentInstruction(ws, &err);

    ret = x86GetDebugProcessStatus(ws, PT_CONTINUE, waitval, data);
    if (ret != 1)
    {
      /*
       * Something stopped the program (breakpoint, signal, exit, etc)
       */
      return (ret);
    }

    /*
     * If we get here it we most likely hit a breakpoint which
     * was ignored, so singlestep past the breakpoint instruction
     * and continue tracing the process
     */
    ret = x86DoSingleStep(ws, data);
    if (ret != 1)
      return (ret); /* something stopped the process */
  } /* while (1) */
} /* x86DoContinue() */

/*
x86stepIntoDebug()
  Single step our program, stepping into any subroutines

Inputs: ws   - debug workspace
        num  - number of instructions to step through
        data - modified to contain info depending on the return
               result, see below

Return: 0 if unsuccessful
        1 if successful
        2 if program stops due to a signal
        3 if breakpoint is encountered
        4 if program terminates

Side effects: If the process stops due to a signal, data is
              modified to contain the signal number.
              If the process hits a breakpoint, the breakpoint
              number is put into data
              If the process terminates normally, data is modified
              to contain the exit status.
*/

int
x86stepIntoDebug(struct debugWorkspace *ws, int num, int *data)

{
  int ii;
  int ret;

  assert(num > 0);

  if (ws->pid == NOPID)
  {
    ret = x86execDebug(ws);
    if (ret == 2)
      return (6); /* not an executable file */
    else if (ret == 0)
      return (0); /* something went wrong */
  }

  dbSetRunning(ws);

  for (ii = 0; ii < num; ++ii)
  {
    /*
     * Perform single step
     */
    ret = x86DoSingleStep(ws, data);
    if (ret != 1)
    {
      /*
       * Something stopped the process (signal, breakpoint, exit, etc)
       */
      return (ret);
    }
  } /* for (ii = 0; ii < num; ++ii) */

  /*
   * All went well
   */
  return (1);
} /* x86stepIntoDebug() */

/*
x86stepOverDebug()
  Single step our program, stepping past any subroutines

Inputs: ws   - debug workspace
        num  - number of instructions to step over
        data - modified to contain info depending on the return
               result, see below

Return: 0 if unsuccessful
        1 if successful
        2 if program stops due to a signal
        3 if breakpoint encountered
        4 if program terminates

Side effects: If the process stops due to a signal, data is
              modified to contain the signal number.
              If the process stops due to a breakpoint, data is
              modified to contain the breakpoint number.
              If the process terminates normally, data is modified
              to contain the exit status.
*/

int
x86stepOverDebug(struct debugWorkspace *ws, int num, int *data)

{
  int ii,
      dret,             /* return value from dump memory routine */
      pret;             /* return value from a ptrace function */
  unsigned long slen;   /* length of subroutine call opcode */
  unsigned char *opbuf; /* contains potential call opcode */

  assert(num > 0);

  if (ws->pid == NOPID)
  {
    int ret;

    ret = x86execDebug(ws);
    if (ret == 2)
      return (6); /* not an executable file */
    else if (ret == 0)
      return (0); /* something went wrong */
  }

  dbSetRunning(ws);

  for (ii = 0; ii < num; ++ii)
  {
    slen = 0;
    opbuf = 0;

    /*
     * Dump 20 bytes of memory so we can tell if we are about
     * to enter a subroutine
     */
    dret = x86dumpMemoryDebug(ws, &opbuf, ws->instructionPointer, 20);

    if (opbuf)
    {
      if (dret > 0)
        slen = IsSubroutine(opbuf);

      free(opbuf);
    }

    if (slen)
    {
      int bret;
      unsigned long baddr;

      /*
       * We are about to enter a subroutine - set a breakpoint
       * at location ws->instructionPointer + slen.
       */
      baddr = (unsigned long) (ws->instructionPointer + slen);
      bret = setAndSaveBreakpoint(ws, baddr, BK_TEMPORARY | BK_STEPOVER);

      /*
       * Now continue until we hit the breakpoint
       */
      pret = x86DoContinue(ws, data);

      if (pret == 3)
      {
        if (*data == 0)
        {
          /*
           * A value of 0 means we hit the temporary breakpoint
           * at the address after the call instruction - so we
           * do not need to inform the user about it. Continue
           * stepping.
           */
          continue;
        }

        /*
         * It is most likely a breakpoint which was set inside
         * of the subroutine we were trying to step over. It
         * could also be a breakpoint at the exact address we set
         * our temporary breakpoint.
         */
        return (3);
      }
      else
      {
        /*
         * 'data' will have been set appropriately by
         * x86GetDebugProcessStatus()
         */
        return (pret);
      }
    } /* if (slen) */

    /*
     * We are not about to enter a subroutine - just step
     * one instruction
     */
    pret = x86DoSingleStep(ws, data);
    if (pret != 1)
    {
      /*
       * Something happened (signal, breakpoint, exit, etc)
       */
      return (pret);
    }
  } /* for (ii = 0; ii < num; ++ii) */

  /*
   * All went well
   */
  return (1);
} /* x86stepOverDebug() */

/*
x86continueDebug()
  Continue the debugged process where it left off

Inputs: ws   - debug workspace
        data - modified to contain info depending on return value

Return: 0 if unsuccessful
        1 if successful
        2 if program stops due to a signal (signal put into data)
        3 if breakpoint encountered (brk pt number put into data)
        4 if program terminates (exit status put into data)
        6 if program is not executable
        7 if program terminates due to a signal (signal num put into data)
*/

int
x86continueDebug(struct debugWorkspace *ws, int *data)

{
  if (ws->pid == NOPID)
  {
    int ret;

    ret = x86execDebug(ws);
    if (ret == 2)
      return (6); /* not an executable file */
    else if (ret == 0)
      return (0); /* something went wrong */
  }

  dbSetRunning(ws);

  return (x86DoContinue(ws, data));
} /* x86continueDebug() */

/*
x86attachDebug()
  Attach to a currently running process

Inputs: ws  - debug workspace
        pid - process id

Return: 1 if successful, 0 if not
*/

int
x86attachDebug(struct debugWorkspace *ws, int pid)

{
  int err;
  int waitval;

  if (ptrace(PT_ATTACH, pid, 0, 0) != 0)
    return (0); /* something went wrong */

  wait(&waitval);

  ws->pid = (pid_t) pid;

  /*
   * Set the instruction pointer to the program's current position
   */
  err = 0;
  ws->instructionPointer = x86getCurrentInstruction(ws, &err);
  if (err)
  {
    /*
     * The most likely cause of this is that the file is not
     * executable
     */
    ws->pid = NOPID;
    return (0);
  }

  dbSetAttached(ws);
  dbSetRunning(ws);

  return (1);
} /* x86attachDebug() */

/*
x86detachDebug()
  Detach from current process

Inputs: ws - debug workspace

Return: -1 if not currently attached
        0 if ptrace fails
        pid of detached process if successful
*/

int
x86detachDebug(struct debugWorkspace *ws)

{
  int waitval;
  int pid;

  if (!dbIsAttached(ws))
    return (-1);

  if (ptrace(PT_DETACH, ws->pid, 0, 0) != 0)
    return (0); /* something went wrong */

  wait(&waitval);

  pid = ws->pid;

  ws->pid = NOPID;
  dbClearAttached(ws);
  dbClearRunning(ws);

  return (pid);
} /* x86detachDebug() */

/*
x86killDebug()
  Kill current debugged process

Return: 1 if successful
        0 if not
*/

int
x86killDebug(struct debugWorkspace *ws)

{
  int ret;
  int waitval;

  if (ws->pid != NOPID)
  {
    ret = ptrace(PT_KILL, ws->pid, 0, 0);

    if (ret == 0)
      wait(&waitval);
  }

  return (1);
} /* x86killDebug() */

/*
x86saveBreakpoint()
  Save the contents of a breakpoint's memory location, so we can restore it later

Inputs: ws   - debug workspace
        bptr - breakpoint structure containing info

Return: 1 if successful
        0 if not
*/

int
x86saveBreakpoint(struct debugWorkspace *ws, struct Breakpoint *bptr)

{
  int saved; /* saved instruction */

  assert(bptr != 0);
  assert(ws->pid != NOPID);

#if 0
  if (ws->pid == NOPID)
  {
    if (x86execDebug(ws) == 0)
      return (0); /* something went wrong */
  }
#endif

  /*
   * Save lowest byte of the dword at the break address
   */
  saved = PtraceRead(ws->pid, bptr->address, 0);
  if (saved == (-1))
    return (0); /* error - most likely EIO */

  bptr->svdinsn = saved;

  return (1);
} /* x86saveBreakpoint() */

/*
x86enableBreakpoint()
  Enable breakpoint by setting the first byte of it's
memory address to the breakpoint instruction

Return: 1 if successful
        0 if not
*/

int
x86enableBreakpoint(struct debugWorkspace *ws, struct Breakpoint *bptr)

{
  int insn;
  int data;

  assert(ws->pid != NOPID);
  assert(bptr != 0);

  /*
   * We must read the contents of bptr->address again, even though we have
   * previously saved the contents of that location. The reason for this is
   * the following scenario: If we set 2 breakpoints, within 4 bytes of each other,
   * when we enable the first, we stick a 0xCC in the first byte of it's location.
   * If the second breakpoint occurs before the first in memory, we will overwrite
   * the original 0xCC when writing the modified word for the second breakpoint.
   * Unfortunately, ptrace cannot be used to write a single byte without disturbing
   * adjacent bytes.
   */
  data = PtraceRead(ws->pid, bptr->address, 0);
  if (data == (-1))
    return (0); /* error - most likely EIO */

  /*
   * This is little-endian specific
   */
  insn = (data & ~0x000000FF) | BRKPT_INSN;

#if 0
  insn = (bptr->svdinsn & ~0xFF) | BRKPT_INSN;
#endif

  /*
   * Replace the instruction with our breakpoint instruction
   */
  if (PtraceWrite(ws->pid, bptr->address, insn) != 0)
    return (0);

  return (1);
} /* x86enableBreakpoint() */

/*
x86disableBreakpoint()
  Restore breakpoint address with it's original instruction

Return: 1 if successful
        0 if not
*/

int
x86disableBreakpoint(struct debugWorkspace *ws, struct Breakpoint *bptr)

{
  assert(ws->pid != NOPID);
  assert(bptr != 0);

  /*
   * Replace the instruction with our saved instruction
   */
  if (PtraceWrite(ws->pid, bptr->address, bptr->svdinsn) != 0)
    return (0);

  return (1);
} /* x86disableBreakpoint() */

/*
x86dumpMemoryDebug()
  Dump memory contents of debugged process

Inputs: ws    - debug workspace
        buf   - buffer to store memory bytes in
        start - address to start dump
        bytes - number of bytes to dump

Return: number of bytes dumped - if this is less than 'bytes',
        an error occurred, and errno should be set appropriately.

Side effects: space is allocated for 'buf', so it must be freed by
              the calling function
*/

long
x86dumpMemoryDebug(struct debugWorkspace *ws, unsigned char **buf,
                   unsigned long start, unsigned long bytes)

{
  int wordval;
  unsigned long addr, /* current address we are examining */
                end;  /* last address to examine */
  unsigned char *bufptr;
  long ret;           /* return value */

  if (ws->pid == NOPID)
  {
    if (x86execDebug(ws) == 0)
      return (0); /* something went wrong */
  }

  addr = start;

  end = start + bytes;
  if (end < start)
    return (0); /* integer overflow */

  if ((bytes + 1) == 0)
    return (0); /* integer overflow */

  *buf = (char *) malloc(bytes + 1);
  if (*buf == NULL)
    return (0);

  bufptr = (unsigned char *) *buf;

  ret = 0;

  while (addr < end)
  {
    wordval = PtraceRead(ws->pid, addr, 0);
    if ((wordval == (-1)) && (errno == EIO))
    {
      /*
       * Input/output error
       */
      return (ret);
    }

    /*
     * The ptrace() call will return a 2 byte (word) value on
     * intel systems, and little-endian will put the byte at
     * the address 'addr' last, so anding with 0xff will separate
     * that byte.
     */
    *bufptr++ = (unsigned char) (wordval & 0xff);

    ++addr;
    ++ret;
  } /* while (addr <= end) */

  *bufptr = '\0';

  return (ret);
} /* x86dumpMemoryDebug() */

/*
x86setMemoryDebug()
  Set the contents of memory location 'address' to 'value'

Inputs: ws      - debug workspace
        address - memory address
        value   - value to set

Return: 0 if unsuccessful (ptrace error)
        number of bytes written if successful
*/

int
x86setMemoryDebug(struct debugWorkspace *ws, unsigned long address, unsigned long value)

{
  int wordval;
  int ret;
  unsigned int mask;

  if (ws->pid == NOPID)
  {
    if (x86execDebug(ws) == 0)
      return (0); /* something went wrong */
  }

  /*
   * An interesting note about ptrace() - although it is documented
   * to return a "word", it actually returns the size of an int,
   * in this case 32 bits, when it should actually return 16 bits,
   * the size of an intel word.
   * This works for PtraceWrite() too - it writes a 32 bit quantity
   * to the address you specify.
   */
  wordval = PtraceRead(ws->pid, address, 0);
  if (wordval == (-1))
    return (0);

  ret = 0;

  /*
   * Determine how many bytes the calling program wants to write
   * to memory - if we simply try to write the 32 bit quantity
   * 'value', and it is a 1 byte number, we will overwrite 3 bytes
   * of memory with zeros
   */
  if ((value & 0xff) == value)
  {
    ret = 1; /* we are setting 1 byte */
    mask = 0xffffff00;
  }
  else if ((value & 0xffff) == value)
  {
    ret = 2; /* we are setting 2 bytes */
    mask = 0xffff0000;
  }
  else if ((value & 0xffffff) == value)
  {
    ret = 3; /* we are setting 3 bytes */
    mask = 0xff000000;
  }
  else
  {
    ret = 4; /* we are setting 4 bytes */
    mask = 0x00000000;
  }

  /*
   * Clear the byte(s) we are about to change
   */
  wordval &= mask;

  /*
   * Set the new byte(s)
   */
  wordval |= value;

  if (PtraceWrite(ws->pid, address, wordval) != 0)
    return (0);

  return (ret);
} /* x86setMemoryDebug() */
