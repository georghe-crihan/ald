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
 * $Id: libOFF.h,v 1.1.1.1 2004/04/26 00:40:41 pa33 Exp $
 */

#ifndef INCLUDED_libOFF_libOFF_h
#define INCLUDED_libOFF_libOFF_h

#define OFF_MAXLINE     1024

#ifndef INCLUDED_libOFF_fmt_aout_h
#include "fmt_aout.h"       /* struct aoutWorkspace */
#define INCLUDED_libOFF_fmt_aout_h
#endif

#ifndef INCLUDED_libOFF_fmt_elf_h
#include "fmt_elf.h"        /* struct elfWorkspace */
#define INCLUDED_libOFF_fmt_elf_h
#endif

#ifndef INCLUDED_libOFF_version_h
#include "version.h"
#define INCLUDED_libOFF_version_h
#endif

struct offParameters
{
  unsigned int virtualFileAddress;      /* virtual address of file beginning */
  unsigned int virtualEntryPoint;       /* virtual address of entry point */
  unsigned int entryPoint;              /* entry point of object file */
};

struct offWorkspace
{
  struct aoutWorkspace *aoutWorkspace_p;  /* a.out workspace */
  struct elfWorkspace *elfWorkspace_p;    /* elf workspace */

  int platformEndian;                     /* endianness of platform */
  int fileType;                           /* object file type (OFF_TYPE_xxx) */
};

/*
 * This struct is filled in by findSectionOFF()
 */
struct offSectionInfo
{
  char *name;                          /* section name */
  unsigned int address;                /* section address */
  unsigned int offset;                 /* offset into section */
  unsigned int size;                   /* section size */
};

/*
 * This struct is filled in by findSymbolOFF()
 */
struct offSymbolInfo
{
  char *name;                          /* symbol name */
  unsigned int address;                /* symbol address */
  unsigned int offset;                 /* offset into symbol */
  unsigned int size;                   /* symbol size */
};

/*
 * Object file types
 */

#define OFF_TYPE_NONE       0  /* no object file currently loaded */
#define OFF_TYPE_UNKNOWN    1  /* unknown object format */
#define OFF_TYPE_AOUT       2  /* a.out format */
#define OFF_TYPE_ELF        3  /* executable and linkable format (ELF) */

/*
 * Endian types
 */

#define OFF_ENDIAN_LITTLE   0  /* little endian */
#define OFF_ENDIAN_BIG      1  /* big endian */

/*
 * Prototypes
 */

struct offWorkspace *initOFF();
void termOFF(struct offWorkspace *ws);
int identifyOFF(struct offWorkspace *ws, void *ptr, size_t size,
                struct offParameters *params, char *str);
unsigned long loadSymbolsOFF(struct offWorkspace *ws);
void unloadSymbolsOFF(struct offWorkspace *ws);
int findSectionOFF(struct offWorkspace *ws, char *name,
                   unsigned int address, struct offSectionInfo *secinfo);
int findSymbolOFF(struct offWorkspace *ws, char *name,
                  unsigned int address, struct offSymbolInfo *syminfo);
void printHeaderOFF(struct offWorkspace *ws,
                    void (*callback)(void *, const char *, ...),
                    void *args);
void printSectionInfoOFF(struct offWorkspace *ws, char *sname,
                         void (*callback)(void *, const char *, ...),
                         void *args);
void printSymbolsOFF(struct offWorkspace *ws, char *name,
                     void (*callback)(void *, const char *, ...),
                     void *args);

/*
 * External declarations
 */

extern char *EndianTypeOFF[];

#endif /* INCLUDED_libOFF_libOFF_h */
