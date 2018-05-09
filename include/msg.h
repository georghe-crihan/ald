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
 * $Id: msg.h,v 1.1.1.1 2004/04/26 00:41:11 pa33 Exp $
 */

#ifndef INCLUDED_msg_h
#define INCLUDED_msg_h

/*
 * Contains various string constants for use throughout
 * the program
 */

#define MSG_NOFILELOADED    "No file has been loaded (see help load)"
#define MSG_PROGDONE        "Program terminated normally (Exit status: 0x%04X)"
#define MSG_PROGNOEXEC      "%s: file is not executable"
#define MSG_INVNUM          "Invalid number: %s"
#define MSG_INVADDR         "Invalid address: %s"
#define MSG_INVSYM          "Invalid symbol: %s"
#define MSG_PTERR           "Error in ptrace(): %s"
#define MSG_BKPTENCOUNTERED "Breakpoint %d encountered at 0x%08lX"
#define MSG_GOTSIGNAL       "\nProgram received signal %s (%s)\nLocation: 0x%08lX"
#define MSG_GOTUNKNOWNSIG   "\nProgram received unknown signal %d\nLocation: 0x%08lX"
#define MSG_NOACCESS        "Unable to access memory at location 0x%08X: %s"
#define MSG_NOPROCESS       "No process is currently being debugged"
#define MSG_PROGTERMSIG     "Program terminated with signal %s (%s)"
#define MSG_PROGTERMUNKNOWNSIG "Program terminated with unknown signal %d"

#endif /* INCLUDED_msg_h */
