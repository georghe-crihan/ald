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
 * $Id: config.h,v 1.1.1.1 2004/04/26 00:41:11 pa33 Exp $
 */

#ifndef INCLUDED_config_h
#define INCLUDED_config_h

/*
 * Define this to enable debugging mode
 */

#define DEBUGMODE

#ifdef DEBUGMODE

/*
 * Define this to the filename to log all debugging information to
 */

#define DEBUGLOG    "./debug.log"

#endif /* DEBUGMODE */

#endif /* INCLUDED_config_h */
