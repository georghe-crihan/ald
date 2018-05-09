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
 * $Id: signals.h,v 1.1.1.1 2004/04/26 00:41:12 pa33 Exp $
 */

#ifndef INCLUDED_signals_h
#define INCLUDED_signals_h

struct aSignal
{
  char *name; /* signal name */
  char *desc; /* description */
};

/*
 * These must match the array indices of Signals[]
 */
#define MYSIG_ZERO          0
#define MYSIG_HUP           1
#define MYSIG_INT           2
#define MYSIG_QUIT          3
#define MYSIG_ILL           4
#define MYSIG_TRAP          5
#define MYSIG_ABRT          6
#define MYSIG_EMT           7
#define MYSIG_FPE           8
#define MYSIG_KILL          9
#define MYSIG_BUS           10
#define MYSIG_SEGV          11
#define MYSIG_SYS           12
#define MYSIG_PIPE          13
#define MYSIG_ALRM          14
#define MYSIG_TERM          15
#define MYSIG_URG           16
#define MYSIG_STOP          17
#define MYSIG_TSTP          18
#define MYSIG_CONT          19
#define MYSIG_CHLD          20
#define MYSIG_TTIN          21
#define MYSIG_TTOU          22
#define MYSIG_IO            23
#define MYSIG_XCPU          24
#define MYSIG_XFSZ          25
#define MYSIG_VTALRM        26
#define MYSIG_PROF          27
#define MYSIG_WINCH         28
#define MYSIG_LOST          29
#define MYSIG_USR1          30
#define MYSIG_USR2          31
#define MYSIG_PWR           32
#define MYSIG_POLL          33

/*
 * Prototypes
 */
struct aSignal *GetSignal(int signum);
void SetupSignals();
void SigHandler(int sig);

#endif /* INCLUDED_signals_h */
