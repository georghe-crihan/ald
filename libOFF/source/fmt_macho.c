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
 * $Id: fmt_elf.c,v 1.1.1.1 2004/04/26 00:40:36 pa33 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#include <strings.h>

#include "cfgOFF.h"
#include "fmt_macho.h"
#include "libOFF.h"
#include "symbols.h"

#ifdef FIXME
static Macho_Shdr *locateSectionByNameELF(struct elfWorkspace *ws,
                                          char *name);
static Macho_Shdr *locateSectionByAddressELF(struct elfWorkspace *ws,
                                             unsigned int address);
static Elf32_Sym *locateSymbolByNameELF(struct elfWorkspace *ws,
                                        char *name);
static Elf32_Sym *locateSymbolByAddressELF(struct elfWorkspace *ws,
                                           unsigned int address);
static int callbackPrintSymbolELF(void *data, void *params);
static int callbackCompareSymbolNameELF(void *data, void *params);
static int callbackCompareSymbolAddressELF(void *data, void *params);
#endif

static char *MachoClass[] = {
  "Invalid class",             /* ELFCLASSNONE */
  "32 bit",                    /* ELFCLASS32 */
  "64 bit"                     /* ELFCLASS64 */
};

static char *MachoData[] = {
  "Invalid data",              /* ELFDATANONE */
  "LSB - little endian",       /* ELFDATA2LSB */
  "MSB - big endian",          /* ELFDATA2MSB */
};

#ifdef FIXME
static char *ElfOSABI[] = {
  "None Specified",                   /* ELFOSABI_NONE */
  "Hewlett-Packard HP-UX",            /* ELFOSABI_HPUX */
  "NetBSD",                           /* ELFOSABI_NETBSD */
  "Linux",                            /* ELFOSABI_LINUX */
  0,                                  /* 4 - unused */
  0,                                  /* 5 - unused */
  "Sun Solaris",                      /* ELFOSABI_SOLARIS */
  "AIX",                              /* ELFOSABI_AIX */
  "IRIX",                             /* ELFOSABI_IRIX */
  "FreeBSD",                          /* ELFOSABI_FREEBSD */
  "Compaq TRU64 UNIX",                /* ELFOSABI_TRU64 */
  "Novell Modesto",                   /* ELFOSABI_MODESTO */
  "OpenBSD",                          /* ELFOSABI_OPENBSD */
  "OpenVMS",                          /* ELFOSABI_OPENVMS */
  "Hewlett-Packard Non-Stop Kernel"   /* ELFOSABI_NSK */
                                      /* 64-255 - Architecture specific */
};

static char *ElfType[] = {
  "No file type",              /* ET_NONE */
  "Relocatable",               /* ET_REL */
  "Executable",                /* ET_EXEC */
  "Shared Object",             /* ET_DYN */
  "Core file"                  /* ET_CORE */
};

static char *ElfMachine[] = {
  "No machine",                                          /* EM_NONE */
  "AT&T WE 32100",                                       /* EM_M32 */
  "SUN SPARC",                                           /* EM_SPARC */
  "Intel 80386",                                         /* EM_386 */
  "Motorola m68k family",                                /* EM_68K */
  "Motorola m88k family",                                /* EM_88K */
  0,                                                     /* 6 reserved (was EM_486) */
  "Intel 80860",                                         /* EM_860 */
  "MIPS R3000 big-endian",                               /* EM_MIPS */
  "IBM System/370 Processor",                            /* EM_S370 */
  "MIPS RS3000 Little-endian",                           /* EM_MIPS_RS3_LE */
  0,                                                     /* 11 - reserved */
  0,                                                     /* 12 - reserved */
  0,                                                     /* 13 - reserved */
  0,                                                     /* 14 - reserved */
  "Hewlett-Packard PA-RISC",                             /* EM_PARISC */
  0,                                                     /* 16 - reserved */
  "Fujitsu VPP500",                                      /* EM_VPP500 */
  "Enhanced instruction set SPARC",                      /* EM_SPARC32PLUS */
  "Intel 80960",                                         /* EM_960 */
  "PowerPC",                                             /* EM_PPC */
  "64-bit PowerPC",                                      /* EM_PPC64 */
  "IBM System/390 Processor",                            /* EM_S390 */
  0,                                                     /* 23 - reserved */
  0,                                                     /* 24 - reserved */
  0,                                                     /* 25 - reserved */
  0,                                                     /* 26 - reserved */
  0,                                                     /* 27 - reserved */
  0,                                                     /* 28 - reserved */
  0,                                                     /* 29 - reserved */
  0,                                                     /* 30 - reserved */
  0,                                                     /* 31 - reserved */
  0,                                                     /* 32 - reserved */
  0,                                                     /* 33 - reserved */
  0,                                                     /* 34 - reserved */
  0,                                                     /* 35 - reserved */
  "NEC V800",                                            /* EM_V800 */
  "Fujitsu FR20",                                        /* EM_FR20 */
  "TRW RH-32",                                           /* EM_RH32 */
  "Motorola RCE",                                        /* EM_RCE */
  "Advanced RISC Machines ARM",                          /* EM_ARM */
  "Digital Alpha",                                       /* EM_ALPHA */
  "Hitachi SH",                                          /* EM_SH */
  "SPARC Version 9",                                     /* EM_SPARCV9 */
  "Siemens TriCore embedded processor",                  /* EM_TRICORE */
  "Argonaut RISC Core",                                  /* EM_ARC */
  "Hitachi H8/300",                                      /* EM_H8_300 */
  "Hitachi H8/300H",                                     /* EM_H8_300H */
  "Hitachi H8S",                                         /* EM_H8S */
  "Hitachi H8/500",                                      /* EM_H8_500 */
  "Intel IA-64 processor architecture",                  /* EM_IA_64 */
  "Stanford MIPS-X",                                     /* EM_MIPS_X */
  "Motorola ColdFire",                                   /* EM_COLDFIRE */
  "Motorola M68HC12",                                    /* EM_68HC12 */
  "Fujitsu MMA Multimedia Accelerator",                  /* EM_MMA */
  "Siemens PCP",                                         /* EM_PCP */
  "Sony nCPU embedded RISC processor",                   /* EM_NCPU */
  "Denso NDR1 microprocessor",                           /* EM_NDR1 */
  "Motorola Star*Core processor",                        /* EM_STARCORE */
  "Toyota ME16 processor",                               /* EM_ME16 */
  "STMicroelectronics ST100 processor",                  /* EM_ST100 */
  "Advanced Logic Corp. TinyJ embedded processor",       /* EM_TINYJ */
  "AMD x86-64 architecture",                             /* EM_X86_64 */
  "Sony DSP Processor",                                  /* EM_PDSP */
  "Digital Equipment Corp. PDP-10",                      /* EM_PDP10 */
  "Digital Equipment Corp. PDP-11",                      /* EM_PDP11 */
  "Siemens FX66 microcontroller",                        /* EM_FX66 */
  "STMicroelectronics ST9+ 8/16 bit microcontroller",    /* EM_ST9PLUS */
  "STMicroelectronics ST7 8-bit microcontroller",        /* EM_ST7 */
  "Motorola MC68HC16 Microcontroller",                   /* EM_68HC16 */
  "Motorola MC68HC11 Microcontroller",                   /* EM_68HC11 */
  "Motorola MC68HC08 Microcontroller",                   /* EM_68HC08 */
  "Motorola MC68HC05 Microcontroller",                   /* EM_68HC05 */
  "Silicon Graphics SVx",                                /* EM_SVX */
  "STMicroelectronics ST19 8-bit microcontroller",       /* EM_ST19 */
  "Digital VAX",                                         /* EM_VAX */
  "Axis Communications 32-bit embedded processor",       /* EM_CRIS */
  "Infineon Technologies 32-bit embedded processor",     /* EM_JAVELIN */
  "Element 14 64-bit DSP Processor",                     /* EM_FIREPATH */
  "LSI Logic 16-bit DSP Processor",                      /* EM_ZSP */
  "Donald Knuth's educational 64-bit processor",         /* EM_MMIX */
  "Harvard University machine-independent object files", /* EM_HUANY */
  "SiTera Prism",                                        /* EM_PRISM */
  "Atmel AVR 8-bit microcontroller",                     /* EM_AVR */
  "Fujitsu FR30",                                        /* EM_FR30 */
  "Mitsubishi D10V",                                     /* EM_D10V */
  "Mitsubishi D30V",                                     /* EM_D30V */
  "NEC v850",                                            /* EM_V850 */
  "Mitsubishi M32R",                                     /* EM_M32R */
  "Matsushita MN10300",                                  /* EM_MN10300 */
  "Matsushita MN10200",                                  /* EM_MN10200 */
  "picoJava",                                            /* EM_PJ */
  "OpenRISC 32-bit embedded processor",                  /* EM_OPENRISC */
  "ARC Cores Tangent-A5",                                /* EM_ARC_A5 */
  "Tensilica Xtensa Architecture",                       /* EM_XTENSA */
  "Alphamosaic VideoCore processor",                     /* EM_VIDEOCORE */
  "Thompson Multimedia General Purpose Processor",       /* EM_TMM_GPP */
  "National Semiconductor 32000 series",                 /* EM_NS32K */
  "Tenor Network TPC processor",                         /* EM_TPC */
  "Trebia SNP 1000 processor",                           /* EM_SNP1K */
  "STMicroelectronics ST200 microcontroller"             /* EM_ST200 */
};

static char *ElfVersion[] = {
  "Invalid version",           /* EV_NONE */
  "Current"                    /* EV_CURRENT */
};

static char *SectionType[] = {
  "inactive",                             /* SHT_NULL */
  "program specific",                     /* SHT_PROGBITS */
  "symbol table",                         /* SHT_SYMTAB */
  "string table",                         /* SHT_STRTAB */
  "relocation entries",                   /* SHT_RELA */
  "symbol hash table",                    /* SHT_HASH */
  "dynamic linking data",                 /* SHT_DYNAMIC */
  "note",                                 /* SHT_NOTE */
  "no bits",                              /* SHT_NOBITS */
  "relocation entries",                   /* SHT_REL */
  "reserved",                             /* SHT_SHLIB */
  "dynamic symbol table",                 /* SHT_DYNSYM */
  0,                                      /* 12 - reserved */
  0,                                      /* 13 - reserved */
  "initialization array",                 /* SHT_INIT_ARRAY */
  "termination array",                    /* SHT_FINI_ARRAY */
  "pre-initialization array",             /* SHT_PREINIT_ARRAY */
  "section group",                        /* SHT_GROUP */
  "associated with symbol table section"  /* SHT_SYMTAB_SHNDX */
};

/*
 * Contains information on each SHF_xxx flag contained in
 * the 'sh_flags' field
 */
static struct elfFlagsInfo SectionFlags[] = {
  { SHF_WRITE, "Writable" },
  { SHF_ALLOC, "Occupies memory during exection" },
  { SHF_EXECINSTR, "Contains executable instructions" },
  { SHF_MERGE, "Section elements may be merged" },
  { SHF_STRINGS, "Section elements consist of character strings" },
  { SHF_INFO_LINK, "Holds a section header table index" },
  { SHF_LINK_ORDER, "Contains special ordering requirements for link editors" },
  { SHF_OS_NONCONFORMING, "Requires special OS-specific processing" },
  { SHF_GROUP, "Member of a section group" },
  { SHF_TLS, "Thread-Local Storage" },
  { SHF_MASKOS, "Operating system specific semantics" },
  { SHF_MASKPROC, "Processor specific semantics" },

  { 0, 0 }
};

static char *SymbolBinding[] = {
  "local",                     /* STB_LOCAL */
  "global",                    /* STB_GLOBAL */
  "weak",                      /* STB_WEAK */
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "processor specific",        /* STB_LOPROC */
  "processor specific",
  "processor specific"         /* STB_HIPROC */
};

static char *SymbolType[] = {
  "unknown",                   /* STT_NOTYPE */
  "data object",               /* STT_OBJECT */
  "function",                  /* STT_FUNC */
  "section",                   /* STT_SECTION */
  "file",                      /* STT_FILE */
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "processor specific",        /* STT_LOPROC */
  "processor specific",
  "processor specific"         /* STT_HIPROC */
};
#endif

/*
initMACHO()
  Initialize an elf workspace

Return: pointer to new workspace
*/

struct machoWorkspace *
initMACHO()

{
  struct machoWorkspace *ws;

  ws = (struct machoWorkspace *) malloc(sizeof(struct machoWorkspace));
  if (!ws)
  {
    fprintf(stderr, "initMACHO: malloc failed: %s\n", strerror(errno));
    return (0);
  }

  memset(ws, '\0', sizeof(struct machoWorkspace));

  ws->symbolWorkspace_p = initSYM();
  if (!ws->symbolWorkspace_p)
  {
    termMACHO(ws);
    return (0);
  }

  return (ws);
} /* initMACHO() */

/*
termMACHO()
  Terminate an elf workspace

Inputs: ws - workspace to terminate
*/

void
termMACHO(struct machoWorkspace *ws)

{
  if (!ws)
    return;

  if (ws->symbolWorkspace_p)
    termSYM(ws->symbolWorkspace_p);

  free(ws);
} /* termMACHO() */

/*
checkMACHO()
  Check whether a file is a MACHO file

Inputs: ws             - macho workspace
        ptr            - pointer to mapped file in memory
        size           - size of file
        params         - where to store parameters
        str            - where to store errors
        platformEndian - endianness of our platform

Return: 1 if file is MACHO (identification string goes in str)

        0 if file is not MACHO

        -1 if file is not MACHO and we have an error message to
        report (error goes in str)
*/

int
checkMACHO(struct machoWorkspace *ws, void *ptr, size_t size,
         struct machoParameters *params, char *str, int platformEndian)

{
#ifdef FIXME
  Elf32_Ehdr *ElfHeader;
  Elf32_Phdr *ProgramHeader;
  Elf32_Shdr *SectionTable;
  char *StringTable;
  Elf32_Shdr *sptr;
  int elfEndian;
#endif
  unsigned int virtualFileAddress,
               virtualEntryPoint,
               entryPoint;

  assert(ptr != 0);

#ifdef FIXME
  /*
   * Make sure the file is at least as big as the ELF header
   */
  if (size < sizeof(Elf32_Ehdr))
    return (0);

  ElfHeader = (Elf32_Ehdr *) ptr;

  if ((ElfHeader->e_ident[EI_MAG0] != ELFMAG0) ||
      (ElfHeader->e_ident[EI_MAG1] != ELFMAG1) ||
      (ElfHeader->e_ident[EI_MAG2] != ELFMAG2) ||
      (ElfHeader->e_ident[EI_MAG3] != ELFMAG3))
  {
    /*
     * Invalid ELF header
     */
    return (0);
  }

  if (ElfHeader->e_ident[EI_CLASS] >= ELFCLASSNUM)
    return (0);

  if (ElfHeader->e_ident[EI_DATA] >= ELFDATANUM)
    return (0);

  if (ElfHeader->e_ident[EI_DATA] == ELFDATA2LSB)
    elfEndian = OFF_ENDIAN_LITTLE;
  else
    elfEndian = OFF_ENDIAN_BIG;

  if (elfEndian != platformEndian)
  {
    /*
     * The endian-ness of the target file differs from the endian-ness
     * of the machine we are running on.
     */
    sprintf(str,
            "checkELF: %s file differs from %s platform",
            EndianTypeOFF[(unsigned char) elfEndian],
            EndianTypeOFF[(unsigned char) platformEndian]);
    return (-1);
  }

  if (ElfHeader->e_type >= ET_NUM)
    return (0);

  if (ElfHeader->e_machine >= EM_NUM)
    return (0);

  if (ElfHeader->e_version >= EV_NUM)
    return (0);

  assert(ElfMachine[(unsigned char) ElfHeader->e_machine] != 0);

  virtualEntryPoint = ElfHeader->e_entry;

  ProgramHeader = (Elf32_Phdr *) ((char *)ElfHeader + ElfHeader->e_phoff);
  if (!INSIDE_FILE_ELF(ptr, size, ProgramHeader) ||
      ((unsigned char *)ProgramHeader > ((unsigned char *)ptr +
                                         size -
                                         sizeof(Elf32_Phdr))))
  {
    sprintf(str,
            "checkELF: invalid header field e_phoff: %u",
            ElfHeader->e_phoff);
    return (-1);
  }

  if ((ElfHeader->e_shoff != 0) && (ElfHeader->e_shnum != 0))
  {
    SectionTable = (Elf32_Shdr *) ((char *) ElfHeader + ElfHeader->e_shoff);
    if (!INSIDE_FILE_ELF(ptr, size, SectionTable) ||
        ((unsigned char *)SectionTable > ((unsigned char *)ptr +
                                          size -
                                          sizeof(Elf32_Shdr))))
    {
      sprintf(str,
              "checkELF: invalid header field e_shoff: %u",
              ElfHeader->e_shoff);
      return (-1);
    }
  }
  else
    SectionTable = 0;

  if (!SectionTable || (ElfHeader->e_shstrndx == SHN_UNDEF))
  {
    /*
     * There is no string table present in this file
     */
    StringTable = 0;
  }
  else
  {
    /*
     * The location of the string table is inside one of the
     * structures in the section header table, given by the index
     * e_shstrndx (ie: SectionTable + ElfHeader->e_shstrndx*sizeof(Elf32_Shdr))
     */
    sptr = SectionTable + ElfHeader->e_shstrndx;
    if (sptr->sh_type != SHT_STRTAB)
    {
      sprintf(str,
              "checkELF: invalid string table section type: %u",
              sptr->sh_type);
      return (-1);
    }

    StringTable = (char *) ElfHeader + sptr->sh_offset;
    if (!INSIDE_FILE_ELF(ptr, size, StringTable) ||
        ((unsigned char *)StringTable > ((unsigned char *)ptr +
                                         size -
                                         sizeof(char *))))
    {
      sprintf(str,
              "checkELF: invalid header field e_shstrndx: %u",
              ElfHeader->e_shstrndx);
      return (-1);
    }
  }

  if (ProgramHeader->p_vaddr != 0)
  {
    virtualFileAddress = (unsigned int)
                         (ProgramHeader->p_vaddr - ProgramHeader->p_offset);

    entryPoint = virtualEntryPoint - virtualFileAddress;
  }
  else
    virtualFileAddress = virtualEntryPoint = entryPoint = 0;

  sprintf(str,
          "ELF %s (%s), %s, %s, Version %d (%s)",
          ElfMachine[(unsigned char) ElfHeader->e_machine],
          ElfClass[(unsigned char) ElfHeader->e_ident[EI_CLASS]],
          ElfData[(unsigned char) ElfHeader->e_ident[EI_DATA]],
          ElfType[(unsigned char) ElfHeader->e_type],
          ElfHeader->e_version,
          ElfVersion[(unsigned char) ElfHeader->e_version]);

  ws->ElfHeader = ElfHeader;
  ws->ProgramHeader = ProgramHeader;
  ws->SectionTable = SectionTable;
  ws->StringTable = StringTable;
  ws->symbolStringTable = 0;

  ws->elfEndian = elfEndian;
  ws->virtualFileAddress = virtualFileAddress;

  params->virtualFileAddress = virtualFileAddress;
  params->virtualEntryPoint = virtualEntryPoint;
  params->entryPoint = entryPoint;
#endif

  return (1);
} /* checkMACHO() */

/*
loadSymbolsMACHO()
  Load macho symbols into memory. Call this AFTER checkMACHO() :-).

Inputs: ws - macho workspace

Return: number of symbols loaded

Side effects: ws->symbolStringTable is configured to the correct value

              ws->symbolWorkspace_p is modified to contain the symbol
              data structure
*/

unsigned long
loadSymbolsMACHO(struct machoWorkspace *ws)

{
#ifdef FIXME
  Elf32_Ehdr *ElfHeader; /* elf header */
  Elf32_Shdr *sptr;      /* temporary section header table entry */
  Elf32_Sym *symtabptr;  /* pointer to symbol table */
  char *strtabptr;       /* pointer to symbol string table */
  Elf32_Half ii;         /* looping */
#endif
  long ii;
  void *symtabptr;
  unsigned long symcnt;  /* number of entries in the symbol table */

#ifdef FIXME
  ElfHeader = ws->ElfHeader;

  if ((ElfHeader->e_shnum == 0) || !ws->SectionTable)
  {
    /*
     * No sections => no symbols
     */
    return (0);
  }

  strtabptr = 0;
  symtabptr = 0;
  symcnt = 0;

  for (ii = 0; ii < ElfHeader->e_shnum; ++ii)
  {
    sptr = ws->SectionTable + ii;

    if (sptr->sh_type == SHT_SYMTAB)
    {
      /*
       * We found a symbol section (.symtab) - there should only
       * be one section with the property of SHT_SYMTAB, so if
       * symtabptr is non-null we have a problem.
       */
      assert(!symtabptr);
      symtabptr = (Elf32_Sym *) ((char *) ElfHeader + sptr->sh_offset);
      symcnt = sptr->sh_size / sptr->sh_entsize;

      /*
       * The string table associated with the symbol table is
       * the section header table index specified by the sh_link field
       */
      strtabptr = (char *) ((char *) ElfHeader +
                            (ws->SectionTable + sptr->sh_link)->sh_offset);
    }
  } /* for (ii = 0; ii < ElfHeader->e_shnum; ++ii) */

  if (!symtabptr)
  {
    /*
     * No symbols found
     */
    return (0);
  }

  assert(strtabptr != 0);

  ws->symbolStringTable = strtabptr;
#endif
  /*
   * Skip the first symbol table entry since it is defined to be
   * a dummy entry
   */
  for (ii = 1; ii < symcnt; ++ii)
    addSYM(ws->symbolWorkspace_p, (void *) (symtabptr + ii));

  return (symcnt);
} /* loadSymbolsMACHO() */

/*
unloadSymbolsMACHO()
  Unload symbols from memory
*/

void
unloadSymbolsMACHO(struct machoWorkspace *ws)

{
  unloadSYM(ws->symbolWorkspace_p);
} /* unloadSymbolsMACHO() */

/*
findSectionMACHO()
  Find a section by name or address

Inputs: ws      - macho workspace
        name    - section name
        address - section address
        secinfo - where to store result

NOTE: To search by section name set address = 0
      To search by section address set name = 0

Return: 1 if section found
        0 if not found
*/

int
findSectionMACHO(struct machoWorkspace *ws, char *name, 
               unsigned int address, struct machoSectionInfo *secinfo)

{
#ifdef FIXME
  Elf32_Shdr *secptr;
#endif

  if (!ws->SectionTable)
    return (0); /* no sections */

  if (name)
  {
#ifdef FIXME
    secptr = locateSectionByNameMACHO(ws, name);
    if (!secptr)
      return (0);

    secinfo->name = ws->StringTable + secptr->sh_name;
    /*secinfo->address = secptr->sh_addr;*/
    secinfo->address = ws->virtualFileAddress + secptr->sh_offset;
    secinfo->offset = 0;

    if (secptr->sh_type == SHT_NOBITS)
      secinfo->size = 0;
    else
      secinfo->size = secptr->sh_size;
  }
  else
  {
    secptr = locateSectionByAddressMACHO(ws, address);
    if (!secptr)
      return (0);

    secinfo->name = ws->StringTable + secptr->sh_name;
    /*secinfo->address = secptr->sh_addr;*/
    secinfo->address = ws->virtualFileAddress + secptr->sh_offset;
    secinfo->offset = address - secptr->sh_addr;

    if (secptr->sh_type == SHT_NOBITS)
      secinfo->size = 0;
    else
      secinfo->size = secptr->sh_size;
#endif
  }
  return (1);
} /* findSectionMACHO() */

/*
findSymbolMACHO()
  Find a symbol by name or address

Inputs: ws      - macho workspace
        name    - symbol name
        address - symbol address
        syminfo - where to store result

NOTE: To search by symbol name set address = 0
      To search by symbol address set name = 0

Return: 1 if symbol found
        0 if not found
*/

int
findSymbolMACHO(struct machoWorkspace *ws, char *name,
              unsigned int address, struct machoSymbolInfo *syminfo)

{
#ifdef FIXME
  Elf32_Sym *symptr;

  if (!ws->symbolStringTable)
    return (0);

  if (name)
  {
    /*
     * Find symbol by name
     */

    symptr = locateSymbolByNameMACHO(ws, name);
    if (!symptr)
      return (0);

    syminfo->address = symptr->st_value;
    syminfo->offset = 0;
    syminfo->name = ws->symbolStringTable + symptr->st_name;
    syminfo->size = symptr->st_size;
  }
  else
  {
    /*
     * Find symbol by address
     */
    symptr = locateSymbolByAddressMACHO(ws, address);
    if (!symptr)
      return (0);

    syminfo->address = symptr->st_value;
    syminfo->offset = address - symptr->st_value;
    syminfo->name = ws->symbolStringTable + symptr->st_name;
    syminfo->size = symptr->st_size;
  }
#endif
  return (1);
} /* findSymbolMACHO() */

/*
printHeaderMACHO()
  Print MACHO header informaton

Inputs: ws       - macho workspace
        callback - function to call to do the actual printing
        args     - callback arguments

Return: none
*/

void
printHeaderMACHO(struct machoWorkspace *ws,
               void (*callback)(void *, const char *, ...),
               void *args)

{
#ifdef FIXME
  Elf32_Ehdr *ElfHeader;
  unsigned int entryOff;
  int dlen;              /* length of field description string */

  ElfHeader = ws->ElfHeader;

  /*
   * We can assume we have a valid ELF header
   */

  (*callback)(args, "Executable and Linkable Format (ELF)");

  dlen = 35;

  (*callback)(args,
              "%-*s 0x%02X (%s)",
              dlen,
              "File Class:",
              ElfHeader->e_ident[EI_CLASS],
              ElfClass[(unsigned char) ElfHeader->e_ident[EI_CLASS]]);

  (*callback)(args,
              "%-*s 0x%02X (%s)",
              dlen,
              "Data encoding:",
              ElfHeader->e_ident[EI_DATA],
              ElfData[(unsigned char) ElfHeader->e_ident[EI_DATA]]);

  (*callback)(args,
              "%-*s 0x%02X (%s)",
              dlen,
              "ELF Header Version:",
              ElfHeader->e_ident[EI_VERSION],
              ElfVersion[(unsigned char) ElfHeader->e_ident[EI_VERSION]]);

  if (ElfOSABI[(unsigned char) ElfHeader->e_ident[EI_OSABI]] != 0)
  {
    (*callback)(args,
                "%-*s 0x%02X (%s)",
                dlen,
                "Operating System ABI:",
                ElfHeader->e_ident[EI_OSABI],
                ElfOSABI[(unsigned char) ElfHeader->e_ident[EI_OSABI]]);
  }

  (*callback)(args,
              "%-*s 0x%02X",
              dlen,
              "ABI Version:",
              ElfHeader->e_ident[EI_ABIVERSION]);

  (*callback)(args,
              "%-*s 0x%04X (%s)",
              dlen,
              "Machine Architecture:",
              ElfHeader->e_machine,
              ElfMachine[(unsigned char) ElfHeader->e_machine]);

  (*callback)(args,
              "%-*s 0x%08X (%s)",
              dlen,
              "Object File Version:",
              ElfHeader->e_version,
              ElfVersion[(unsigned char) ElfHeader->e_version]);

  (*callback)(args,
              "%-*s 0x%04X (%s)",
              dlen,
              "Object File Type:",
              ElfHeader->e_type,
              ElfType[(unsigned char) ElfHeader->e_type]);

  entryOff = ElfHeader->e_entry -
             ws->ProgramHeader->p_vaddr +
             ws->ProgramHeader->p_offset;

  (*callback)(args,
              "%-*s 0x%08X (File Offset: 0x%08X)",
              dlen,
              "Virtual Entry Point:",
              ElfHeader->e_entry,
              entryOff);

  (*callback)(args,
              "%-*s 0x%08X",
              dlen,
              "Program table header offset:",
              ElfHeader->e_phoff);

  (*callback)(args,
              "%-*s 0x%08X",
              dlen,
              "Section table header offset:",
              ElfHeader->e_shoff);

  (*callback)(args,
              "%-*s 0x%08X",
              dlen,
              "Processor specific flags:",
              ElfHeader->e_flags);

  (*callback)(args,
              "%-*s 0x%04X",
              dlen,
              "ELF header size (bytes):",
              ElfHeader->e_ehsize);

  (*callback)(args,
              "%-*s 0x%04X",
              dlen,
              "Program header table entry size:",
              ElfHeader->e_phentsize);

  (*callback)(args,
              "%-*s 0x%04X",
              dlen,
              "Program header table entry count:",
              ElfHeader->e_phnum);

  (*callback)(args,
              "%-*s 0x%04X",
              dlen,
              "Section header table entry size:",
              ElfHeader->e_shentsize);

  (*callback)(args,
              "%-*s 0x%04X",
              dlen,
              "Section header table entry count:",
              ElfHeader->e_shnum);

  if (ElfHeader->e_shstrndx != SHN_UNDEF)
  {
    (*callback)(args,
                "%-*s 0x%04X",
                dlen,
                "Section header string table index:",
                ElfHeader->e_shstrndx);
  }
#endif
} /* printHeaderMACHO() */

/*
printSectionInfoMACHO()
  Print MACHO section informaton

Inputs: ws       - macho workspace
        sname    - optional section name: if not given, all sections
                   will be displayed
        callback - function to call to do the actual printing
        args     - callback arguments

Return: none
*/

void
printSectionInfoMACHO(struct machoWorkspace *ws,
                    char *sname,
                    void (*callback)(void *, const char *, ...),
                    void *args)

{
#ifdef FIXME
  Elf32_Ehdr *ElfHeader;
  Elf32_Shdr *sptr;
  Elf32_Word size;
  Elf32_Half ii;          /* looping */

  ElfHeader = ws->ElfHeader;

  if ((ElfHeader->e_shnum == 0) || !ws->SectionTable)
  {
    (*callback)(args, "No sections found");
    return;
  }

  if (ws->StringTable == 0)
  {
    (*callback)(args, "No section name string table present");
    return;
  }

  if (sname)
  {
    struct elfFlagsInfo *fptr;
    int dlen;               /* length of field description string */

    sptr = locateSectionByNameMACHO(ws, sname);
    if (!sptr)
    {
      (*callback)(args,
                  "No section found matching: %s",
                  sname);
      return;
    }

    dlen = 20;

    (*callback)(args,
                "%-*s %s",
                dlen,
                "Section name:",
                ws->StringTable + sptr->sh_name);

    if (sptr->sh_type < SHT_NUM)
    {
      (*callback)(args,
                  "%-*s 0x%08X (%s)",
                  dlen,
                  "Section type:",
                  sptr->sh_type,
                  SectionType[sptr->sh_type]);
    }
    else if ((sptr->sh_type >= SHT_LOOS) && (sptr->sh_type <= SHT_HIOS))
    {
      (*callback)(args,
                  "%-*s 0x%08X (Operating system specific semantics)",
                  dlen,
                  "Section type:",
                  sptr->sh_type);
    }
    else if ((sptr->sh_type >= SHT_LOPROC) && (sptr->sh_type <= SHT_HIPROC))
    {
      (*callback)(args,
                  "%-*s 0x%08X (Processor specific semantics)",
                  dlen,
                  "Section type:",
                  sptr->sh_type);
    }
    else if ((sptr->sh_type >= SHT_LOUSER) && (sptr->sh_type <= SHT_HIUSER))
    {
      (*callback)(args,
                  "%-*s 0x%08X (Application specific semantics)",
                  dlen,
                  "Section type:",
                  sptr->sh_type);
    }

    (*callback)(args,
                "%-*s 0x%08X",
                dlen,
                "Section flags:",
                sptr->sh_flags);

    /*
     * Print out descriptions of each flag in sh_flags
     */
    for (fptr = SectionFlags; fptr->desc != 0; ++fptr)
    {
      if (sptr->sh_flags & fptr->flag)
      {
        (*callback)(args,
                    "%-*s   %s",
                    dlen,
                    "",
                    fptr->desc);
      }
    }

    (*callback)(args,
                "%-*s 0x%08X",
                dlen,
                "Virtual address:",
                sptr->sh_addr);
    (*callback)(args,
                "%-*s 0x%08X (%d)",
                dlen,
                "Size (bytes):",
                sptr->sh_size,
                sptr->sh_size);
    (*callback)(args,
                "%-*s 0x%08X (%d)",
                dlen,
                "File offset:",
                sptr->sh_offset,
                sptr->sh_offset);
    (*callback)(args,
                "%-*s 0x%08X",
                dlen,
                "Link:",
                sptr->sh_link);
    (*callback)(args,
                "%-*s 0x%08X",
                dlen,
                "Info:",
                sptr->sh_info);

    if ((sptr->sh_addralign != 0) && (sptr->sh_addralign != 1))
    {
      (*callback)(args,
                  "%-*s %d bytes",
                  dlen,
                  "Address alignment:",
                  sptr->sh_addralign);
    }

    if (sptr->sh_entsize != 0)
    {
      (*callback)(args,
                  "%-*s %d bytes",
                  dlen,
                  "Entry size:",
                  sptr->sh_entsize);
    }

    return;
  } /* if (sname) */

  /*
   * They did not give a specific section name - output all
   * sections
   */

  (*callback)(args,
              "%-20s %-13s %-13s %-8s",
              "Section name",
              "Start",
              "End",
              "Length (bytes)");

  for (ii = 0; ii < ElfHeader->e_shnum; ++ii)
  {
    sptr = ws->SectionTable + ii;
    if (sptr->sh_type == SHT_NULL)
      continue; /* unused section */

    /*
     * The MACHO specification says that sh_size can be non-zero if
     * the section is marked as SHT_NOBITS, which means that the
     * section has zero size, so I will special-case this
     */
    if (sptr->sh_type == SHT_NOBITS)
      size = 0;
    else
      size = sptr->sh_size;

    (*callback)(args,
                "%-20s 0x%08X -> 0x%08X    0x%08X",
                ws->StringTable + sptr->sh_name,
                ws->virtualFileAddress + sptr->sh_offset,
                ws->virtualFileAddress + sptr->sh_offset + size,
                size);
  }
#endif
} /* printSectionInfoMACHO() */

/*
printSymbolsMACHO()
  Print MACHO symbol informaton

Inputs: ws       - macho workspace
        symname  - optional symbol name: if not given, all symbols will
                   be printed
        callback - function to call to do the actual printing
        args     - callback arguments

Return: none
*/

void
printSymbolsMACHO(struct machoWorkspace *ws,
                char *symname,
                void (*callback)(void *, const char *, ...),
                void *args)

{
  struct machoCallbackParams callbackArgs;
#ifdef FIXME
  Elf32_Sym *symptr;
  Elf32_Shdr *secptr;
  int dlen;

  if (symname)
  {
    /*
     * They want information on a specific symbol
     */
    symptr = locateSymbolByNameMACHO(ws, symname);
    if (!symptr)
    {
      (*callback)(args,
                  "No symbol found matching: %s",
                  symname);
      return;
    }

    dlen = 25;

    (*callback)(args,
                "%-*s %s",
                dlen,
                "Symbol name:",
                ws->symbolStringTable + symptr->st_name);

    if (symptr->st_value != 0)
    {
      (*callback)(args,
                  "%-*s 0x%08X",
                  dlen,
                  "Symbol address:",
                  symptr->st_value);
    }

    (*callback)(args,
                "%-*s 0x%08X (%d)",
                dlen,
                "Symbol size:",
                symptr->st_size,
                symptr->st_size);

    (*callback)(args,
                "%-*s %s",
                dlen,
                "Symbol binding:",
                SymbolBinding[ELF32_ST_BIND(symptr->st_info)]);

    (*callback)(args,
                "%-*s %s",
                dlen,
                "Symbol type:",
                SymbolType[ELF32_ST_TYPE(symptr->st_info)]);

    if (ws->SectionTable && (symptr->st_shndx < ws->ElfHeader->e_shnum))
    {
      secptr = ws->SectionTable + symptr->st_shndx;
      if (secptr->sh_type != SHT_NULL)
      {
        (*callback)(args,
                    "%-*s %s",
                    dlen,
                    "Section contained in:",
                    ws->StringTable + secptr->sh_name);
      }
    }
  }
  else
  {
    /*
     * Print all symbols
     */

    callbackArgs.ws = ws;
    callbackArgs.printCallback = callback;
    callbackArgs.printCallbackArgs = args;

    (*callback)(args,
                "%-10s %-10s %-20s %-30s %s",
                "Address",
                "Binding",
                "Type",
                "Name",
                "Size");

    traverseSYM(ws->symbolWorkspace_p,
                callbackPrintSymbolMACHO,
                &callbackArgs);
  }
#endif
} /* printSymbolsMACHO() */

/********************************************
 *           INTERNAL ROUTINES              *
 ********************************************/

/*
locateSectionByNameMACHO()
  Locate macho section with the give name, if any and return
a pointer to it

Inputs: ws   - pointer to elf workspace
        name - section name

Return: pointer to section if found, 0 if not
*/

#ifdef FIXME
static Elf32_Shdr *
locateSectionByNameMACHO(struct machoWorkspace *ws, char *name)

{
  Elf32_Ehdr *ElfHeader;   /* elf header */
  Elf32_Shdr *sptr;        /* section pointer */
  Elf32_Half ii;           /* looping */
  char *sname;

  ElfHeader = ws->ElfHeader;

  if ((ElfHeader->e_shnum == 0) || !ws->SectionTable)
    return (0); /* no sections */

  if (ws->StringTable == 0)
    return (0); /* no string table for section names */

  for (ii = 0; ii < ElfHeader->e_shnum; ++ii)
  {
    sptr = ws->SectionTable + ii;

    sname = ws->StringTable + sptr->sh_name;

    if (!strcasecmp(name, sname))
    {
      /*
       * match found
       */
      return (sptr);
    }
  }

  return (0);
} /* locateSectionByNameMACHO() */

/*
locateSectionByAddressMACHO()
  Locate macho section which contains the given address. If found,
return a pointer to it

Inputs: ws      - pointer to macho workspace
        address - section address

Return: pointer to section if found, 0 if not
*/

static Elf32_Shdr *
locateSectionByAddressMACHO(struct machoWorkspace *ws, unsigned int address)

{
  Elf32_Ehdr *ElfHeader;
  Elf32_Shdr *sptr;
  Elf32_Half ii;         /* looping */
  Elf32_Off begin,
            finish;

  ElfHeader = ws->ElfHeader;

  if ((ElfHeader->e_shnum == 0) || !ws->SectionTable)
    return (0); /* no sections */

  for (ii = 0; ii < ElfHeader->e_shnum; ++ii)
  {
    sptr = ws->SectionTable + ii;

    begin = ws->virtualFileAddress + sptr->sh_offset;
    finish = begin + sptr->sh_size;

    if ((address >= begin) && (address <= finish))
    {
      /*
       * We have found the section
       */
      return (sptr);
    }
  }

  return (0);
} /* locateSectionByAddressMACHO() */

/*
locateSymbolByNameMACHO()
  Attempt to locate a symbol by name

Inputs: ws   - macho workspace
        name - symbol name

Return: pointer to symbol if found
        0 if not found
*/

static Elf32_Sym *
locateSymbolByNameMACHO(struct machoWorkspace *ws, char *name)

{
  Elf32_Sym *symptr;
  struct elfCallbackParams callbackArgs;

  callbackArgs.ws = ws;
  callbackArgs.str = name;

  symptr = (Elf32_Sym *) traverseSYM(ws->symbolWorkspace_p,
                                     callbackCompareSymbolNameELF,
                                     &callbackArgs);

  return (symptr);
} /* locateSymbolByNameMACHO() */

/*
locateSymbolByAddressMACHO()
  Attempt to locate a symbol by address

Inputs: ws      - macho workspace
        address - address inside symbol

Return: pointer to symbol if found
        0 if not found
*/

static Elf32_Sym *
locateSymbolByAddressMACHO(struct machoWorkspace *ws, unsigned int address)

{
  Elf32_Sym *symptr;
  struct machoCallbackParams callbackArgs;

  callbackArgs.address = address;

  symptr = (Elf32_Sym *) traverseSYM(ws->symbolWorkspace_p,
                                     callbackCompareSymbolAddressELF,
                                     &callbackArgs);

  return (symptr);
} /* locateSymbolByAddressMACHO() */

/*
callbackPrintSymbolMACHO()
  Backend to printSymbolsMACHO(): called from traverseSYM to print
information on one symbol

Inputs: data   - Elf32_Sym data element describing symbol
        params - struct machoCallbackParams containing useful info

Return: ST_CONTINUE
*/

static int
callbackPrintSymbolMACHO(void *data, void *params)

{
  Elf32_Sym *symptr;
  char addrstr[64];
  struct machoCallbackParams *callbackArgs;
  struct machoWorkspace *ws;
  void (*printCallback)(void *, const char *, ...);
  void *printCallbackArgs;

  symptr = (Elf32_Sym *) data;
  callbackArgs = (struct elfCallbackParams *) params;

  ws = callbackArgs->ws;
  printCallback = callbackArgs->printCallback;
  printCallbackArgs = callbackArgs->printCallbackArgs;

  assert(symptr != 0);
  assert(ws->symbolStringTable != 0);

  if (symptr->st_value != 0)
    sprintf(addrstr, "0x%08X", symptr->st_value);
  else
    *addrstr = 0;

  (*printCallback)(printCallbackArgs,
                   "%-10s %-10s %-20s %-30s %d",
                   addrstr,
                   SymbolBinding[ELF32_ST_BIND(symptr->st_info)],
                   SymbolType[ELF32_ST_TYPE(symptr->st_info)],
                   ws->symbolStringTable + symptr->st_name,
                   symptr->st_size);

  return (ST_CONTINUE);
} /* callbackPrintSymbolMACHO() */

/*
callbackCompareSymbolNameMACHO()
  Backend to locateSymbolByNameMACHO(). Called from traverseSYM() to
see if the current symbol node matches the name we are looking for.

Inputs: data   - symbol node data
        params - symbol name we are looking for

Return: ST_CONTINUE if not a match
        ST_STOP if a match
*/

static int
callbackCompareSymbolNameMACHO(void *data, void *params)

{
  struct machoCallbackParams *callbackArgs;
  struct machoWorkspace *ws;   /* elf workspace */
  Elf32_Sym *symptr;         /* symbol pointer */
  char *name;                /* symbol name */

  symptr = (Elf32_Sym *) data;
  callbackArgs = (struct machoCallbackParams *) params;

  ws = callbackArgs->ws;
  name = callbackArgs->str;

  if (!strcmp(ws->symbolStringTable + symptr->st_name, name))
    return (ST_STOP);

  return (ST_CONTINUE);
} /* callbackCompareSymbolNameMACHO() */

/*
callbackCompareSymbolAddressMACHO()
  Backend to locateSymbolByAddressMACHO(). Called from traverseSYM() to
see if the current symbol node matches the name we are looking for.

Inputs: data   - symbol node data
        params - symbol name we are looking for

Return: ST_CONTINUE if not a match
        ST_STOP if a match
*/

static int
callbackCompareSymbolAddressMACHO(void *data, void *params)

{
  struct machoCallbackParams *callbackArgs;
  Elf32_Sym *symptr;         /* symbol pointer */
  unsigned int address;      /* symbol address */

  symptr = (Elf32_Sym *) data;
  callbackArgs = (struct machoCallbackParams *) params;

  address = callbackArgs->address;

  if ((symptr->st_value != 0) &&
      (address >= symptr->st_value) &&
      (address <= symptr->st_value + symptr->st_size))
    return (ST_STOP);

  return (ST_CONTINUE);
} /* callbackCompareSymbolAddressMACHO() */
#endif
