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
 * $Id: symbols.h,v 1.1.1.1 2004/04/26 00:40:38 pa33 Exp $
 */

#ifndef INCLUDED_libOFF_symbols_h
#define INCLUDED_libOFF_symbols_h

struct aSymbol
{
  struct aSymbol *next;
  void *data;           /* pointer to data for this node */
};

struct symbolWorkspace
{
  struct aSymbol *symbolList;  /* list of symbols */
  unsigned int numSymbols;     /* number of symbols in symbolList */
};

/*
 * traverseSYM() will check the return value of the function
 * passed to it to determine whether to stop traversing the
 * symbol data structure
 */
#define ST_STOP       0  /* stop traversing symbols */
#define ST_CONTINUE   1  /* continue traversing symbols */

/*
 * Prototypes
 */

struct symbolWorkspace *initSYM();
void termSYM(struct symbolWorkspace *ws);
void addSYM(struct symbolWorkspace *ws, void *data);
void *traverseSYM(struct symbolWorkspace *ws,
                  int (*func)(void *data, void *arg),
                  void *param);
void unloadSYM(struct symbolWorkspace *ws);

#endif /* INCLUDED_libOFF_symbols_h */
