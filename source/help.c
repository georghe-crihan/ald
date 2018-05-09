/*
 * Assembly Language Debugger
 *
 * Copyright (C) 2000-2004 Patrick Alken
 * This program comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: help.c,v 1.3 2004/10/10 05:29:50 pa33 Exp $
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "alddefs.h"
#include "command.h"
#include "help.h"
#include "print.h"

/*
 * libString includes
 */

#include "Strn.h"

static struct HelpCmd *GetHelpCommand(char *name, unsigned int *flags);
static void PrintHelpCommand(struct aldWorkspace *ws, struct HelpCmd *hptr);
static void PrintHelpCommands(struct aldWorkspace *ws, struct HelpCmd *array);

static struct HelpCmd GeneralHelp[] = {
  {
    "attach",
    "Attach to a running process",
    "<pid>\n\
\n\
<pid> - process id to attach to",
  },
  {
    "continue",
    "Continue execution of debugged process",
    "\n\
\n\
Alias: c",
  },
  {
    "detach",
    "Detach from current process",
    "\n\
\n\
  Detaches the debugger from the current process (see help attach)",
  },
  {
    "disassemble",
    "Disassembles machine code into assembly language instructions",
    "[start [stop]] [-num <number>] [flags]\n\
\n\
[start [stop]] - Starting and stopping memory locations - All opcodes\n\
                 inside this range will be disassembled. For this to\n\
                 work, you must be working with an executable file.\n\
[-num <num>]   - Number of instructions to disassemble (default: all)\n\
[flags]        - Various flags\n\
\n\
Flags:\n\
  -section <name> - disassemble specific section <name> - you can\n\
                    use the \"file secinfo\" command to get a list\n\
                    of available sections.\n\
\n\
The output of this command is as follows:\n\
<offset> <opcode> <instruction>\n\
\n\
<offset>      - Virtual offset from beginning of file, or memory address\n\
<opcode>      - Machine language instruction\n\
<instruction> - Assembly language instruction\n\
\n\
 Disassembly begins at the address specified by \"set file-offset\",\n\
unless a start/stop memory address is given.\n\
\n\
Alias: d",
  },
  {
    "display",
    "Display memory after single steps",
    "[start]|[register]|[section]|[symbol] [stop] [-num <num>] [-size <value>] [-output <letter>]\n\
\n\
[start]            - Memory address to start from\n\
[register]         - Memory dump begins at register contents\n\
[section]          - Memory dump begins at section start\n\
[symbol]           - Memory dump begins at symbol start\n\
[stop]             - Memory address to stop dump\n\
[-num <num>]       - Number of elements to dump (default: 20)\n\
[-size <value>]    - Size of each element in bytes (default: 1)\n\
[-output <letter>] - Output format for each element (default: x)\n\
  'x' = hexadecimal\n\
  'o' = octal\n\
  'd' = decimal\n\
\n\
Example:\n\
  display -n 50 -s 1 -o x 0xABCD\n\
   After each single step, 50 bytes of memory starting at location\n\
   0xABCD will be printed.\n\
\n\
See also: ldisplay, undisplay"
  },
  {
    "enter",
    "Change the contents of the program's memory",
    "<address> [value]\n\
\n\
<address> - Memory address to change\n\
[value]   - New value\n\
\n\
  If no value is given, you will be prompted for values for\n\
successive memory addresses until a blank value is input.\n\
\n\
Alias: store",
  },
  {
    "examine",
    "Examine the contents of the program's memory",
    "[start]|[register]|[section]|[symbol] [stop] [-num <num>] [-size <value>] [-output <letter>]\n\
\n\
[start]            - Memory address to start from\n\
[register]         - Memory dump begins at register contents\n\
[section]          - Memory dump begins at section start\n\
[symbol]           - Memory dump begins at symbol start\n\
[stop]             - Memory address to stop dump\n\
[-num <num>]       - Number of elements to dump (default: 20)\n\
[-size <value>]    - Size of each element in bytes (default: 1)\n\
[-output <letter>] - Output format for each element (default: x)\n\
  'x' = hexadecimal\n\
  'o' = octal\n\
  'd' = decimal\n\
\n\
Example:\n\
  examine -n 50 -s 1 -o x 0xABCD\n\
   Dumps 50 elements each of size 1 byte in hexadecimal format,\n\
   starting at location 0xABCD.\n\
\n\
  If no starting address is given, the address specified in\n\
\"set entry-point\" is used. A register name, section name,\n\
or symbol name may be given in place of a starting address.\n\
\n\
Aliases: e, dump",
  },
  {
    "file",
    "Outputs specified information on current file",
    "<header | secinfo | syminfo>\n\
\n\
header         - Output information about the file's object header\n\
secinfo [name] - Output information about the file's sections. If\n\
                 [name] is given, output information about that\n\
                 specific section.\n\
syminfo [sym]  - Output information about the file's symbols, if any.\n\
                 If [sym] is given, output information about that\n\
                 specific symbol.",
  },
  {
    "help",
    "Displays commands, or gives specific help on commands",
    "[optional commands]",
  },
  {
    "ldisplay",
    "Print list of memory addresses to be displayed after single stepping",
    "\n\
\n\
See also: display, undisplay"
  },
  {
    "load",
    "Loads a new file into memory for debugging",
    "<filename>\n\
\n\
 Previous file, if any, is unloaded first",
  },
  {
    "next",
    "Step one instruction, stepping over any subroutines",
    "[num]\n\
\n\
[num] - number of instructions to step over (default: 1)\n\
\n\
Alias: n",
  },
  {
    "quit",
    "Exit the debugger",
    "",
  },
  {
    "register",
    "Display and/or manipulate the process' registers",
    "[-all] [name [value]]\n\
\n\
[-all]    - display all registers\n\
[name]    - name of a specific register\n\
[[value]] - if a name is given, it is set to this value\n\
\n\
With no arguments, the most common registers are displayed\n\
along with their values.",
  },
  {
    "run",
    "Start program from beginning",
    "[arguments]\n\
\n\
[arguments] - runtime arguments to pass to program - if not supplied,\n\
              the arguments given with \"set args\" are used.\n\
\n\
Alias: r",
  },
  {
    "set",
    "Configure various settings",
    "[option] [value]\n\
\n\
Options:\n\
\n\
  args\n\
  disasm-show-syms\n\
  entry-point\n\
  file-offset\n\
  output\n\
  pause-print\n\
  prompt\n\
  step-display-regs\n\
  step-display-fpregs\n\
  step-display-mmxregs\n\
\n\
Type \"help set <option>\" for more information on <option>",
  },
  {
    "step",
    "Step one instruction, stepping into any subroutines",
    "[num]\n\
\n\
[num] - number of instructions to step through (default: 1)\n\
\n\
Alias: s",
  },
  {
    "undisplay",
    "Remove a display address",
    "<number | all>\n\
\n\
  number - number (can be obtained from \"ldisplay\")\n\
  all    - Delete all display addresses\n\
\n\
See also: display, ldisplay"
  },
  {
    "unload",
    "Unloads the current debug file from memory",
    "",
  },

  { 0, 0, 0 },
};

/*
 * Breakpoint related help
 */
static struct HelpCmd BreakHelp[] = {
  {
    "break",
    "Set a breakpoint",
    "<address | symbol>\n\
\n\
  <address> - This is the break address. It must be set at the first\n\
              byte of the instruction where you wish to break. You\n\
              can use the \"disassemble\" command to determine\n\
              where a specific instruction begins.\n\
  <symbol> -  Alternatively, you can specify a debugging symbol\n\
              such as the name of a function. The executable must\n\
              have been compiled with debugging symbols enabled.",
  },
  {
    "dbreak",
    "Delete a breakpoint",
    "<number | all>\n\
\n\
  number - Breakpoint number (can be obtained from \"lbreak\")\n\
  all    - Delete all breakpoints\n\
\n\
Alias: delete",
  },
  {
    "disable",
    "Disable a breakpoint",
    "<number | all>\n\
\n\
  number - Breakpoint number (can be obtained from \"lbreak\")\n\
  all    - Disable all breakpoints\n\
\n\
 When a breakpoint is disabled, it has no effect until it is\n\
reactivated using the \"enable\" command.",
  },
  {
    "enable",
    "Reenable a breakpoint",
    "<number | all>\n\
\n\
  number - Breakpoint number (can be obtained from \"lbreak\")\n\
  all    - Enable all breakpoints\n\
\n\
 This reverses the effect of the \"disable\" command.",
  },
  {
    "ignore",
    "Set the ignore count for a breakpoint",
    "<number> <count>\n\
\n\
  number - Breakpoint number (can be obtained from \"lbreak\")\n\
  count  - New ignore count\n\
\n\
 When a breakpoint has an ignore count set, it will not be\n\
triggered until it has been hit <count> times.",
  },
  {
    "lbreak",
    "List all breakpoints",
    "",
  },
  {
    "tbreak",
    "Set a temporary breakpoint",
    "<address>\n\
\n\
  <address> - Breakpoint address\n\
\n\
 A temporary breakpoint is cleared after the first time it is hit.",
  },

  { 0, 0, 0 }
};

/*
 * Help for set subcommands
 */
static struct HelpCmd SetHelp[] = {
  {
    "set args",
    "Set runtime arguments passed to program",
    "[arguments]",
  },
  {
    "set disasm-show-syms",
    "Display symbol information while disassembling",
    "<on | off>\n\
\n\
 When this option is enabled, the disassemble command will display\n\
which symbol the current instruction resides in, as well as the offset\n\
from the symbol start.",
  },
  {
    "set entry-point",
    "Set the address of the program's entry point",
    "<absolute address>\n\
\n\
 The address specified is taken as an offset from the beginning of\n\
the file, not the virtual address.",
  },
  {
    "set file-offset",
    "Set file offset pointer",
    "<absolute address>\n\
\n\
 This value is used by the \"disassemble\" command to determine\n\
where to begin disassembling the current file. The address\n\
specified here is absolute, not virtual.",
  },
  {
    "set output",
    "Enable output to a file",
    "<filename>\n\
\n\
 When a filename is given, all text written to the current window\n\
will also be written to the file. This is useful for saving\n\
disassembled output, etc.",
  },
  {
    "set pause-print",
    "Enable/disable pausing during print bursts",
    "<on | off>\n\
\n\
 When this option is enabled, commands which display a large amount\n\
of information at one time will prompt the user to continue\n\
displaying after each pageful. Otherwise all the data will be dumped\n\
to the screen with no pauses.",
  },
  {
    "set prompt",
    "Configure the command prompt",
    "<new prompt>\n\
\n\
 Sets the command line prompt to <new prompt>. Use quotes if\n\
<new prompt> contains spaces.",
  },
  {
    "set step-display-regs",
    "Display registers after single stepping",
    "<on | off>\n\
\n\
 When this option is enabled, all registers and their contents will\n\
be displayed by the \"step\" and \"next\" commands.",
  },
  {
    "set step-display-fpregs",
    "Display FPU registers after single stepping",
    "<on | off>\n\
\n\
 When this option is enabled, floating point unit (fpu) registers will\n\
be displayed by the \"step\" and \"next\" commands.",
  },
  {
    "set step-display-mmxregs",
    "Display MMX registers after single stepping",
    "<on | off>\n\
\n\
 When this option is enabled, mmx registers will be displayed by the\n\
\"step\" and \"next\" commands.",
  },

  { 0, 0, 0 }
};

static struct HelpCmd *AllHelp[] = {
  GeneralHelp,
  BreakHelp,
  SetHelp,
  0
};

/*
GiveHelp()
 Output help messages to the user on given command. If no
command is given, output general help.

Return: none
*/

void
GiveHelp(struct aldWorkspace *ws, int ac, char **av)

{
  int ii;
  unsigned int flags;
  struct HelpCmd *hptr;
  char str[MAXLINE];
  char *tmp;
  int len;

  if (ac < 2)
  {
    /*
     * No specific command given - output a list of all commands
     */

    startPrintBurst(ws->printWorkspace_p);

    Print(ws,
          P_COMMAND,
          "Commands may be abbreviated.");
    Print(ws,
          P_COMMAND,
          "If a blank command is entered, the last command is repeated.");
    Print(ws,
          P_COMMAND,
          "Type `help <command>' for more specific information on <command>.");
    Print(ws,
          P_COMMAND,
          "");

    Print(ws,
          P_COMMAND,
          "General commands");
    PrintHelpCommands(ws, GeneralHelp);

    Print(ws,
          P_COMMAND,
          "\nBreakpoint related commands");
    PrintHelpCommands(ws, BreakHelp);

    endPrintBurst(ws->printWorkspace_p);

    return;
  }

  /*
   * They want help on a specific command
   */

  len = sizeof(str);

  /*
   * This is needed for commands with spaces in them - such as
   * set <option> - put all the arguments into one buffer to
   * check.
   */
  tmp = str;
  for (ii = 1; ii < ac; ++ii)
  {
    tmp += Snprintf(tmp, len, "%s ", av[ii]);
    len = sizeof(str) - (int) (tmp - str);
  }

  len = (int) (tmp - str);
  if (str[len - 1] == ' ')
    str[len - 1] = '\0';

  flags = 0;
  if ((hptr = GetHelpCommand(str, &flags)))
  {
    PrintHelpCommand(ws, hptr);
    return;
  }

  /*
   * The command they entered was not found - check if they tried
   * to enter multiple commands
   */
  for (ii = 1; ii < ac; ++ii)
  {
    flags = 0;
    hptr = GetHelpCommand(av[ii], &flags);

    if (hptr)
    {
      PrintHelpCommand(ws, hptr);
      continue;
    }

    if (flags & C_AMBIGUOUS)
    {
      /*
       * Ambiguous command
       */
      Print(ws,
            P_COMMAND,
            "Ambiguous command: %s",
            av[ii]);
    }
    else
    {
      /*
       * Unknown command
       */
      Print(ws,
            P_COMMAND,
            "Unknown command: %s",
            av[ii]);
    }
  } /* for (ii = 1; ii < ac; ++ii) */
} /* GiveHelp() */

/*
GetHelpCommand()
 Attempt to find a help command

Inputs: name  - command name
        flags - various bitmasks

Return: pointer to the index containing "name" if found,
        otherwise NULL.
        If the command is found, but there is more than 1 match
        (ambiguous), set the C_AMBIGUOUS bit in 'flags'
*/

static struct HelpCmd *
GetHelpCommand(char *name, unsigned int *flags)

{
  struct HelpCmd *cmdptr,
                 **hptr,
                 *tmp;
  int matches, /* number of matches we've had so far */
      exactmatch;
  size_t clength;
  int bhelp;   /* have we searched the breakpoint commands yet? */

  assert(name != 0);

  bhelp = 0;
  tmp = NULL;
  matches = 0;
  exactmatch = 0;
	cmdptr = 0;
  clength = strlen(name);

  for (hptr = AllHelp; *hptr; ++hptr)
  {
    cmdptr = *hptr;
    for (cmdptr = *hptr; cmdptr->name; ++cmdptr)
    {
      if (!Strncasecmp(name, cmdptr->name, clength))
      {
        if (clength == strlen(cmdptr->name))
        {
          /*
           * name and cmdptr->name are the same length, so it
           * must be an exact match, don't search any further
           */
          exactmatch = 1;
          break;
        }
        tmp = cmdptr;
        ++matches;
      }
    } /* for (cmdptr = *hptr; cmdptr->name; ++cmdptr) */

    if (exactmatch)
    {
      matches = 0;
      break;
    }
  } /* for (hptr = AllHelp; *hptr; ++hptr) */

  /*
   * If matches > 1, name is an ambiguous command, so the
   * user needs to be more specific
   */
  if ((matches == 1) && (tmp))
    cmdptr = tmp;

  assert(cmdptr != 0);

  if (cmdptr->name)
    return (cmdptr);

  if (matches != 0)
    *flags |= C_AMBIGUOUS; /* multiple matches found */

  return (0);
} /* GetHelpCommand() */

/*
PrintHelpCommand()
  Output the information contained in 'hptr'
*/

static void
PrintHelpCommand(struct aldWorkspace *ws, struct HelpCmd *hptr)

{
  assert(hptr != 0);

  startPrintBurst(ws->printWorkspace_p);

  Print(ws,
        P_COMMAND,
        "\n%s: %s",
        hptr->name,
        hptr->desc);

  Print(ws,
        P_COMMAND,
        "Usage: %s %s\n",
        hptr->name,
        hptr->usage);

  endPrintBurst(ws->printWorkspace_p);
} /* PrintHelpCommand() */

/*
PrintHelpCommands()
  Output a list of help commands

Inputs: ws    - ald workspace
        array - array to use

Return: none
*/

static void
PrintHelpCommands(struct aldWorkspace *ws, struct HelpCmd *array)

{
  int cnt = 0;
  char buffer[MAXLINE];
  char *bufptr;
  struct HelpCmd *hptr;

  assert(array != 0);

  *buffer = '\0';
  bufptr = buffer;

  for (hptr = array; hptr->name; ++hptr)
  {
    if (cnt == 5)
    {
      cnt = 0;
      *bufptr = '\0';
      Print(ws, P_COMMAND, "%s", buffer);
      *buffer = '\0';
      bufptr = buffer;
    }

    bufptr += sprintf(bufptr, "%-15s", hptr->name);

    ++cnt;
  }

  if (*buffer)
    Print(ws, P_COMMAND, "%s", buffer);
} /* PrintHelpCommands() */
