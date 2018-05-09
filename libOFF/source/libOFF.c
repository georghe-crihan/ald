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
 * $Id: libOFF.c,v 1.1.1.1 2004/04/26 00:40:38 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "fmt_aout.h"
#include "fmt_elf.h"
#include "libOFF.h"

char *EndianTypeOFF[] = {
  "little endian",     /* OFF_ENDIAN_LITTLE */
  "big endian"         /* OFF_ENDIAN_BIG */
};

/*
initOFF()
  Initialize an OFF workspace

Return: pointer to new workspace
*/

struct offWorkspace *
initOFF()

{
  struct offWorkspace *ws;
  union
  {
    long l;
    char c[sizeof(long)];
  } end_u;

  ws = (struct offWorkspace *) malloc(sizeof(struct offWorkspace));
  if (!ws)
  {
    fprintf(stderr, "initOFF: malloc failed: %s\n", strerror(errno));
    return (0);
  }

  memset(ws, '\0', sizeof(struct offWorkspace));

  /*
   * Initialize a.out workspace
   */
  ws->aoutWorkspace_p = initAOUT();
  if (!ws->aoutWorkspace_p)
  {
    termOFF(ws);
    return (0);
  }

  /*
   * Initialize elf workspace
   */
  ws->elfWorkspace_p = initELF();
  if (!ws->elfWorkspace_p)
  {
    termOFF(ws);
    return (0);
  }

  /*
   * Determine the endianness of this platform
   */
  end_u.l = 1;
  if (end_u.c[sizeof(long) - 1] == 1)
    ws->platformEndian = OFF_ENDIAN_BIG;
  else
    ws->platformEndian = OFF_ENDIAN_LITTLE;

  ws->fileType = OFF_TYPE_NONE;

  return (ws);
} /* initOFF() */

/*
termOFF()
  Terminate an OFF workspace

Inputs: ws - workspace to terminate
*/

void
termOFF(struct offWorkspace *ws)

{
  if (!ws)
    return;

  if (ws->aoutWorkspace_p)
    termAOUT(ws->aoutWorkspace_p);

  if (ws->elfWorkspace_p)
    termELF(ws->elfWorkspace_p);

  free(ws);
} /* termOFF() */

/*
identifyOFF()
  Identify the format of an object file

Inputs: ws     - off workspace
        ptr    - pointer to mapped file (result of mmap())
        size   - file size
        params - where to store file parameters
        str    - where to store file information

Return: OFF_TYPE_xxx representing object file format (file description goes in str)

        -1 if something went wrong and there is an error to report
        (error goes in str)

Side effects: upon a successful identification, the appropriate fields
              of 'params' are filled in with their correct values
*/

int
identifyOFF(struct offWorkspace *ws, void *ptr, size_t size,
            struct offParameters *params, char *str)

{
  int ret;
  struct aoutParameters aoutParams;
  struct elfParameters elfParams;

  /*
   * Check if file is ELF
   */
  ret = checkELF(ws->elfWorkspace_p,
                 ptr,
                 size,
                 &elfParams,
                 str,
                 ws->platformEndian);

  if (ret < 0)
    return (ret); /* there is an error message in str */
  else if (ret == 1)
  {
    /*
     * The file is ELF
     */
    params->virtualFileAddress = elfParams.virtualFileAddress;
    params->virtualEntryPoint = elfParams.virtualEntryPoint;
    params->entryPoint = elfParams.entryPoint;

    ws->fileType = OFF_TYPE_ELF;

    return (OFF_TYPE_ELF);
  }

  /*
   * Check if file is a.out
   */
  ret = checkAOUT(ws->aoutWorkspace_p,
                  ptr,
                  size,
                  &aoutParams,
                  str);

  if (ret != 0)
  {
    /*
     * The file is a.out
     */
    params->virtualFileAddress = 0;
    params->virtualEntryPoint = aoutParams.virtualEntryPoint;
    params->entryPoint = aoutParams.entryPoint;

    ws->fileType = OFF_TYPE_AOUT;

    return (OFF_TYPE_AOUT);
  }

  return (OFF_TYPE_UNKNOWN);
} /* identifyOFF() */

/*
loadSymbolsOFF()
  Call after identifyOFF() to load any symbols from the file into
memory

Inputs: ws - off workspace

Return: number of symbols loaded
*/

unsigned long
loadSymbolsOFF(struct offWorkspace *ws)

{
  switch (ws->fileType)
  {
    case OFF_TYPE_ELF:
    {
      return (loadSymbolsELF(ws->elfWorkspace_p));

      break;
    }

    default:
    {
      break;
    }
  } /* switch (ws->fileType) */

  return (0);
} /* loadSymbolsOFF() */

/*
unloadSymbolsOFF()
  Called after we are finished working with the current file -
free the memory taken up by symbols

Inputs: ws - off workspace

Return: none
*/

void
unloadSymbolsOFF(struct offWorkspace *ws)

{
  switch (ws->fileType)
  {
    case OFF_TYPE_ELF:
    {
      unloadSymbolsELF(ws->elfWorkspace_p);

      break;
    }

    default:
    {
      break;
    }
  } /* switch (ws->fileType) */
} /* unloadSymbolsOFF() */

/*
findSectionOFF()
  Find a section by name or address

Inputs: ws      - off workspace
        name    - section name
        address - address inside section
        secinfo - where to store result

NOTE: To search for the section by name, set address = 0
      To search for the section by address, set name = NULL

Return: 1 if section found
        0 if not
*/

int
findSectionOFF(struct offWorkspace *ws, char *name,
               unsigned int address, struct offSectionInfo *secinfo)

{
  int ret;
  struct elfSectionInfo elfSecInfo;
  struct aoutSectionInfo aoutSecInfo;

  ret = 0;

  switch (ws->fileType)
  {
    case OFF_TYPE_ELF:
    {
      ret = findSectionELF(ws->elfWorkspace_p,
                           name,
                           address,
                           &elfSecInfo);

      if (ret)
      {
        secinfo->name = elfSecInfo.name;
        secinfo->address = elfSecInfo.address;
        secinfo->size = elfSecInfo.size;
        secinfo->offset = elfSecInfo.offset;
      }

      break;
    } /* case OFF_TYPE_ELF */

    case OFF_TYPE_AOUT:
    {
      ret = findSectionAOUT(ws->aoutWorkspace_p,
                            name,
                            address,
                            &aoutSecInfo);

      if (ret)
      {
        secinfo->name = aoutSecInfo.name;
        secinfo->address = aoutSecInfo.address;
        secinfo->size = aoutSecInfo.size;
        secinfo->offset = aoutSecInfo.offset;
      }
    } /* case OFF_TYPE_AOUT */

    default:
    {
      break;
    }
  } /* switch (ws->fileType) */

  return (ret);
} /* findSectionOFF() */

/*
findSymbolOFF()
  Find a symbol by name or address

Inputs: ws      - off workspace
        name    - symbol name
        address - symbol address
        syminfo - where to store result

NOTE: To search for the symbol by name, set address = 0
      To search for the symbol by address, set name = NULL

Return: 1 if symbol found
        0 if not
*/

int
findSymbolOFF(struct offWorkspace *ws, char *name,
              unsigned int address, struct offSymbolInfo *syminfo)

{
  int ret;
  struct elfSymbolInfo elfSymInfo;

  ret = 0;

  switch (ws->fileType)
  {
    case OFF_TYPE_ELF:
    {
      ret = findSymbolELF(ws->elfWorkspace_p,
                          name,
                          address,
                          &elfSymInfo);

      if (ret)
      {
        syminfo->address = elfSymInfo.address;
        syminfo->offset = elfSymInfo.offset;
        syminfo->name = elfSymInfo.name;
        syminfo->size = elfSymInfo.size;
      }

      break;
    }

    default:
    {
      break;
    }
  } /* switch (ws->fileType) */

  return (ret);
} /* findSymbolOFF() */

/*
printHeaderOFF()
  Print header information about the object file we are working with

Inputs: ws       - off workspace
        callback - pointer to callback function - this function
                   will be called to do the actual printing. This
                   function is called similarly to printf:
        args     - callback arguments

                   (*callback)(args, "format string here", arguments here)

Return: none
*/

void
printHeaderOFF(struct offWorkspace *ws,
               void (*callback)(void *, const char *, ...),
               void *args)

{
  switch (ws->fileType)
  {
    case OFF_TYPE_ELF:
    {
      printHeaderELF(ws->elfWorkspace_p, callback, args);

      break;
    }

    case OFF_TYPE_AOUT:
    {
      printHeaderAOUT(ws->aoutWorkspace_p, callback, args);

      break;
    }

    default:
    {
      break;
    }
  } /* switch (ws->fileType) */
} /* printHeaderOFF() */

/*
printSectionInfoOFF()
  Print section information about our object file

Inputs: ws       - off workspace
        sname    - optional section name: if not given, all sections
                   will be displayed
        callback - pointer to callback function - this function
                   will be called to do the actual printing. This
                   function is called similarly to printf:
        args     - callback arguments

                   (*callback)(args, "format string here", arguments here)

Return: none
*/

void
printSectionInfoOFF(struct offWorkspace *ws,
                    char *sname,
                    void (*callback)(void *, const char *, ...),
                    void *args)

{
  switch (ws->fileType)
  {
    case OFF_TYPE_ELF:
    {
      printSectionInfoELF(ws->elfWorkspace_p, sname, callback, args);

      break;
    }

    case OFF_TYPE_AOUT:
    {
      printSectionInfoAOUT(ws->aoutWorkspace_p, sname, callback, args);

      break;
    }

    default:
    {
      break;
    }
  } /* switch (ws->fileType) */
} /* printSectionInfoOFF() */

/*
printSymbolsOFF()
  Print symbols in our object file.

NOTE: loadSymbolsOFF() should be called prior to this function

Inputs: ws       - off workspace
        name     - optional symbol name: if not given, all symbols
                   will be displayed
        callback - pointer to callback function - this function
                   will be called to do the actual printing. This
                   function is called similarly to printf:
        args     - callback arguments

                   (*callback)(args, "format string here", arguments here)

Return: none
*/

void
printSymbolsOFF(struct offWorkspace *ws,
                char *name,
                void (*callback)(void *, const char *, ...),
                void *args)

{
  switch (ws->fileType)
  {
    case OFF_TYPE_ELF:
    {
      printSymbolsELF(ws->elfWorkspace_p, name, callback, args);

      break;
    }

    default:
    {
      break;
    }
  } /* switch (ws->fileType) */
} /* printSymbolsOFF() */
