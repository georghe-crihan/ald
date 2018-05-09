/*
 * libString
 *
 * Copyright (C) 1998-1999 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: Strn.h,v 1.1.1.1 2004/04/26 00:40:55 pa33 Exp $
 */

#ifndef INCLUDED_Strn_h
#define INCLUDED_Strn_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>        /* size_t */
#define INCLUDED_sys_types_h
#endif

#ifndef INCLUDED_stdarg_h
#include <stdarg.h>          /* va_list */
#define INCLUDED_stdarg_h
#endif

/*
 * Prototypes
 */

char *Strncpy(char *dest, const char *source, const size_t bytes);
int Strncasecmp(const char *s1, const char *s2, register size_t n);
int Strcasecmp(const char *s1, const char *s2);
char *Strdup(char *string);
int vSnprintf(register char *dest, register const size_t bytes,
              register char *format, register va_list args);
int vSprintf(register char *dest, register char *format,
             register va_list args);
int Snprintf(register char *dest, register const size_t bytes,
             register char *format, ...);
int Sprintf(register char *dest, register char *format, ...);
int SplitBuffer(char *buffer, char ***array);
int SplitBufferDelim(char *buffer, char ***array, unsigned char delim);

/*
 * External declarations
 */
extern char             libStringVersion[];

#endif /* INCLUDED_Strn_h */
