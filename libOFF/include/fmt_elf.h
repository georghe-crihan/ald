/*
 * Assembly Language Debugger
 *
 * Copyright (C) 2003 Patrick Alken
 * This program comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this program is distributed.
 *
 * $Id: fmt_elf.h,v 1.3 2004/10/09 17:26:54 pa33 Exp $
 */

#ifndef INCLUDED_libOFF_fmt_elf_h
#define INCLUDED_libOFF_fmt_elf_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#ifndef INCLUDED_api_cfgOFF_h
#include "api_cfgOFF.h"        /* uint* */
#define INCLUDED_api_cfgOFF_h
#endif

#ifdef HAVE_INTTYPES_H
# ifndef INCLUDED_inttypes_h
# include <inttypes.h>     /* uint* */
# define INCLUDED_inttypes_h
# endif
#endif /* HAVE_INTTYPES_H */

#ifndef INCLUDED_libOFF_symbols_h
#include "symbols.h"       /* struct symbolWorkspace */
#define INCLUDED_libOFF_symbols_h
#endif

typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;
typedef uint16_t Elf32_Section;
typedef uint8_t Elf32_Char;

typedef	uint64_t Elf64_Addr;
typedef	uint64_t Elf64_Off;
typedef uint16_t Elf64_Section;
typedef uint64_t Elf64_Xword;

typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef uint8_t Elf64_Char;

#define EI_NIDENT     16

/* ELF header */
typedef struct {
  unsigned char e_ident[EI_NIDENT]; /* magic number and other info */
  Elf32_Half e_type;                /* object type */
  Elf32_Half e_machine;             /* architecture */
  Elf32_Word e_version;             /* object version */
  Elf32_Addr e_entry;               /* entry point */
  Elf32_Off e_phoff;                /* program header table offset */
  Elf32_Off e_shoff;                /* section header table offset */
  Elf32_Word e_flags;               /* processor flags */
  Elf32_Half e_ehsize;              /* ELF header size (bytes) */
  Elf32_Half e_phentsize;           /* program header table entry size */
  Elf32_Half e_phnum;               /* program header table entry count */
  Elf32_Half e_shentsize;           /* section header table entry size */
  Elf32_Half e_shnum;               /* section header table entry count */
  Elf32_Half e_shstrndx;            /* section header string table index */
} Elf32_Ehdr;

typedef struct {
  unsigned char e_ident[EI_NIDENT];
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;
  Elf64_Off e_phoff;
  Elf64_Off e_shoff;
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;

/* e_ident[] (magic number) indices */
#define	EI_MAG0         0  /* 1st magic number index */
#define	EI_MAG1         1  /* 2nd magic number index */
#define	EI_MAG2         2  /* 3rd magic number index */
#define	EI_MAG3         3  /* 4th magic number index */
#define	EI_CLASS        4  /* file class index */
#define	EI_DATA         5  /* data encoding index */
#define	EI_VERSION      6  /* file version index */
#define EI_OSABI        7  /* operating system / ABI identification */
#define EI_ABIVERSION   8  /* ABI version */
#define EI_PAD          9  /* start of padding bytes */

/* e_ident[] (magic number) values - put together: \177ELF */
#define	ELFMAG0		      0x7f
#define	ELFMAG1		      'E'
#define	ELFMAG2		      'L'
#define	ELFMAG3		      'F'

/* elf class (e_ident[EI_CLASS]) */
#define ELFCLASSNONE    0  /* invalid class */
#define ELFCLASS32      1  /* 32-bit objects */
#define ELFCLASS64      2  /* 64-bit objects */
#define ELFCLASSNUM     3  /* number of defined classes */

/* elf data (e_ident[EI_DATA]) */
#define ELFDATANONE     0  /* invalid data encoding */
#define ELFDATA2LSB     1  /* 2's complement, little endian */
#define ELFDATA2MSB     2  /* 2's complement, big endian */
#define ELFDATANUM      3  /* number of defined data encodings */

/* elf osabi (e_ident[EI_OSABI]) */
#define ELFOSABI_NONE    0  /* No extensions or unspecified */
#define ELFOSABI_HPUX    1  /* Hewlett-Packard HP-UX */
#define ELFOSABI_NETBSD  2  /* NetBSD */
#define ELFOSABI_LINUX   3  /* Linux */
#define ELFOSABI_SOLARIS 6  /* Sun Solaris */
#define ELFOSABI_AIX     7  /* AIX */
#define ELFOSABI_IRIX    8  /* IRIX */
#define ELFOSABI_FREEBSD 9  /* FreeBSD */
#define ELFOSABI_TRU64   10 /* Compaq TRU64 UNIX */
#define ELFOSABI_MODESTO 11 /* Novell Modesto */
#define ELFOSABI_OPENBSD 12 /* OpenBSD */
#define ELFOSABI_OPENVMS 13 /* OpenVMS */
#define ELFOSABI_NSK     14 /* Hewlett-Packard Non-Stop Kernel */

/* e_type */
#define ET_NONE         0  /* no file type */
#define ET_REL          1  /* relocatable */
#define ET_EXEC         2  /* executable */
#define ET_DYN          3  /* shared object */
#define ET_CORE         4  /* core file */
#define ET_NUM          5  /* number of defined types */

/* e_machine */
#define EM_NONE         0  /* no machine */
#define EM_M32          1  /* AT&T WE 32100 */
#define EM_SPARC        2  /* SUN SPARC */
#define EM_386          3  /* Intel 80386 */
#define EM_68K          4  /* Motorola m68k family */
#define EM_88K          5  /* Motorola m88k family */
/* 6 reserved (was EM_486) */
#define EM_860          7  /* Intel 80860 */
#define EM_MIPS         8  /* MIPS R3000 big-endian */
#define EM_S370         9  /* IBM System/370 Processer */
#define EM_MIPS_RS3_LE  10 /* MIPS Rs3000 little-endian */
/* 11-14 reserved */
#define EM_PARISC       15 /* Hewlett-Packard PA-RISC */
/* 16 reserved */
#define EM_VPP500       17 /* Fujitsu VPP500 */
#define EM_SPARC32PLUS  18 /* Enhanced instruction set SPARC */
#define EM_960          19 /* Intel 80960 */
#define EM_PPC          20 /* PowerPC */
#define EM_PPC64        21 /* 64-bit PowerPC */
#define EM_S390         22 /* IBM System/390 Processor */
/* 23-35 reserved */
#define EM_V800         36 /* NEC V800 */
#define EM_FR20         37 /* Fujitsu FR20 */
#define EM_RH32         38 /* TRW RH-32 */
#define EM_RCE          39 /* Motorola RCE */
#define EM_ARM          40 /* Advanced RISC Machines ARM */
#define EM_ALPHA        41 /* Digital Alpha */
#define EM_SH           42 /* Hitachi SH */
#define EM_SPARCV9      43 /* SPARC Version 9 */
#define EM_TRICORE      44 /* Siemens Tricore embedded processor */
#define EM_ARC          45 /* Argonaut RISC Core, Argonaut Technologies Inc. */
#define EM_H8_300       46 /* Hitachi H8/300 */
#define EM_H8_300H      47 /* Hitachi H8/300H */
#define EM_H8S          48 /* Hitachi H8S */
#define EM_H8_500       49 /* Hitachi H8/500 */
#define EM_IA_64        50 /* Intel IA-64 processor architecture */
#define EM_MIPS_X       51 /* Stanford MIPS-X */
#define EM_COLDFIRE     52 /* Motorola ColdFire */
#define EM_68HC12       53 /* Motorola M68HC12 */
#define EM_MMA          54 /* Fujitsu MMA Multimedia Accelerator */
#define EM_PCP          55 /* Siemens PCP */
#define EM_NCPU         56 /* Sony nCPU embedded RISC processor */
#define EM_NDR1         57 /* Denso NDR1 microprocessor */
#define EM_STARCORE     58 /* Motorola Star*Core processor */
#define EM_ME16         59 /* Toyota ME16 processor */
#define EM_ST100        60 /* STMicroelectronics ST100 processor */
#define EM_TINYJ        61 /* Advanced Logic Corp. TinyJ embedded processor */
#define EM_X86_64       62 /* AMD x86-64 architecture */
#define EM_PDSP         63 /* Sony DSP Processor */
#define EM_PDP10        64 /* Digital Equipment Corp. PDP-10 */
#define EM_PDP11        65 /* Digital Equipment Corp. PDP-11 */
#define EM_FX66         66 /* Siemens FX66 microcontroller */
#define EM_ST9PLUS      67 /* STMicroelectronics ST9+ 8/16 bit microcontroller */
#define EM_ST7          68 /* STMicroelectronics ST7 8-bit microcontroller */
#define EM_68HC16       69 /* Motorola MC68HC16 Microcontroller */
#define EM_68HC11       70 /* Motorola MC68HC11 Microcontroller */
#define EM_68HC08       71 /* Motorola MC68HC08 Microcontroller */
#define EM_68HC05       72 /* Motorola MC68HC05 Microcontroller */
#define EM_SVX          73 /* Silicon Graphics SVx */
#define EM_ST19         74 /* STMicroelectronics ST19 8-bit microcontroller */
#define EM_VAX          75 /* Digital VAX */
#define EM_CRIS         76 /* Axis Communications 32-bit embedded processor */
#define EM_JAVELIN      77 /* Infineon Technologies 32-bit embedded processor */
#define EM_FIREPATH     78 /* Element 14 64-bit DSP Processor */
#define EM_ZSP          79 /* LSI Logic 16-bit DSP Processor */
#define EM_MMIX         80 /* Donald Knuth's educational 64-bit processor */
#define EM_HUANY        81 /* Harvard University machine-independent object files */
#define EM_PRISM        82 /* SiTera Prism */
#define EM_AVR          83 /* Atmel AVR 8-bit microcontroller */
#define EM_FR30         84 /* Fujitsu FR30 */
#define EM_D10V         85 /* Mitsubishi D10V */
#define EM_D30V         86 /* Mitsubishi D30V */
#define EM_V850         87 /* NEC v850 */
#define EM_M32R         88 /* Mitsubishi M32R */
#define EM_MN10300      89 /* Matsushita MN10300 */
#define EM_MN10200      90 /* Matsushita MN10200 */
#define EM_PJ           91 /* pico Java */
#define EM_OPENRISC     92 /* OpenRISC 32-bit embedded processor */
#define EM_ARC_A5       93 /* ARC Cores Tangent-A5 */
#define EM_XTENSA       94 /* Tensilica Xtensa Architecture */
#define EM_VIDEOCORE    95 /* Alphamosaic VideoCore processor */
#define EM_TMM_GPP      96 /* Thompson Multimedia General Purpose Processor */
#define EM_NS32K        97 /* National Semiconductor 32000 series */
#define EM_TPC          98 /* Tenor Network TPC processor */
#define EM_SNP1K        99 /* Trebia SNP 1000 processor */
#define EM_ST200        100 /* STMicroelectronics ST200 microcontroller */
#define EM_NUM          101 /* number of defined machines */


/* e_version */
#define EV_NONE         0  /* invalid ELF version */
#define EV_CURRENT      1  /* current version */
#define EV_NUM          2  /* number of defined versions */

/* Section header */
typedef struct
{
  Elf32_Word sh_name;      /* section name */
  Elf32_Word sh_type;      /* section type */
  Elf32_Word sh_flags;     /* section flags */
  Elf32_Addr sh_addr;      /* virtual address at execution */
  Elf32_Off sh_offset;     /* section file offset */
  Elf32_Word sh_size;      /* section size in bytes */
  Elf32_Word sh_link;      /* link to another section */
  Elf32_Word sh_info;      /* additional information */
  Elf32_Word sh_addralign; /* section alignment */
  Elf32_Word sh_entsize;   /* entry size (if section holds table) */
} Elf32_Shdr;

typedef struct
{
  Elf64_Word sh_name;       /* section name */
  Elf64_Word sh_type;       /* section type */
  Elf64_Xword sh_flags;     /* section flags */
  Elf64_Addr sh_addr;       /* virtual address at execution */
  Elf64_Off sh_offset;      /* section file offset */
  Elf64_Xword sh_size;      /* section size in bytes */
  Elf64_Word sh_link;       /* link to another section */
  Elf64_Word sh_info;       /* additional information */
  Elf64_Xword sh_addralign; /* section alignment */
  Elf64_Xword sh_entsize;   /* entry size (if section holds table) */
} Elf64_Shdr;

/* special section indices */
#define SHN_UNDEF           0      /* undefined section */
#define SHN_LORESERVE       0xff00 /* reserved index lower bound */
#define SHN_LOPROC          0xff00 /* range of processor specific semantics */
#define SHN_HIPROC          0xff1f
#define SHN_LOOS            0xff20 /* range of os specific semantics */
#define SHN_HIOS            0xff3f
#define SHN_ABS             0xfff1 /* absolute values for reference */
#define SHN_COMMON          0xfff2 /* common symbols */
#define SHN_XINDEX          0xffff /* section header index contained elsewhere */
#define SHN_HIRESERVE       0xffff /* reserved index upper bound */

/* sh_type values */
#define SHT_NULL            0  /* section header table entry unused */
#define SHT_PROGBITS        1  /* program data */
#define SHT_SYMTAB          2  /* symbol table */
#define SHT_STRTAB          3  /* string table */
#define SHT_RELA            4  /* relocation entries with addends */
#define SHT_HASH            5  /* symbol hash table */
#define SHT_DYNAMIC         6  /* dynamic linking information */
#define SHT_NOTE            7  /* notes */
#define SHT_NOBITS          8  /* no data (bss) */
#define SHT_REL             9  /* relocation entries with no addends */
#define SHT_SHLIB           10 /* reserved */
#define SHT_DYNSYM          11 /* dynamic linker symbol table */
/* 12-13 reserved */
#define SHT_INIT_ARRAY      14 /* array of pointers to init functions */
#define SHT_FINI_ARRAY      15 /* array of pointers to term functions */
#define SHT_PREINIT_ARRAY   16 /* functions invoked before other init functions */
#define SHT_GROUP           17 /* section group */
#define SHT_SYMTAB_SHNDX    18 /* for SHT_SYMTAB sections with SHN_XINDEX */
#define SHT_NUM             19

#define SHT_LOOS            0x60000000 /* reserved range for operating system */
#define SHT_HIOS            0x6fffffff
#define SHT_LOPROC          0x70000000 /* reserved range for processor */
#define SHT_HIPROC          0x7fffffff
#define SHT_LOUSER          0x80000000 /* reserved range for application */
#define SHT_HIUSER          0xffffffff

/* sh_flags values */
#define SHF_WRITE              (1 << 0)   /* writable */
#define SHF_ALLOC              (1 << 1)   /* occupies memory during execution */
#define SHF_EXECINSTR          (1 << 2)   /* executable */
#define SHF_MERGE              (1 << 3)
#define SHF_STRINGS            (1 << 4)   /* character strings */
#define SHF_INFO_LINK          (1 << 5)   /* holds section header table index */
#define SHF_LINK_ORDER         (1 << 6)   /* special ordering requirements */
#define SHF_OS_NONCONFORMING   (1 << 7)   /* OS specific processing */
#define SHF_GROUP              (1 << 8)   /* member of a section group */
#define SHF_TLS                (1 << 9)   /* thread local storage */
#define SHF_MASKOS             0x0ff00000 /* operating system specific */
#define SHF_MASKPROC           0xf0000000 /* processor specific */

/* Program header */
typedef struct
{
  Elf32_Word p_type;       /* entry type */
  Elf32_Off p_offset;      /* file offset of contents */
  Elf32_Addr p_vaddr;      /* virtual address in memory image */
  Elf32_Addr p_paddr;      /* physical address (not used) */
  Elf32_Word p_filesz;     /* size of contents in file */
  Elf32_Word p_memsz;      /* size of contents in memory */
  Elf32_Word p_flags;      /* access permission flags */
  Elf32_Word p_align;      /* alignment in memory and file */
} Elf32_Phdr;

/* Symbol table entry */
typedef struct
{
  Elf32_Word st_name;      /* symbol name (string table index) */
  Elf32_Addr st_value;     /* symbol value */
  Elf32_Word st_size;      /* symbol size */
  unsigned char st_info;   /* symbol type and binding */
  unsigned char st_other;  /* no defined meaning (0) */
  Elf32_Section st_shndx;  /* section index */
} Elf32_Sym;

#define ELF32_ST_BIND(i)    ((i) >> 4)
#define ELF32_ST_TYPE(i)    ((i) & 0xf)
#define ELF32_ST_INFO(b, t) (((b) << 4) * ((t) & 0xf))

/*
 * Symbol binding (ELF32_ST_BIND)
 */
#define STB_LOCAL       0  /* local symbol */
#define STB_GLOBAL      1  /* global symbol */
#define STB_WEAK        2  /* global symbol with lower precedence */
#define STB_LOPROC      13 /* start of processor specific */
#define STB_HIPROC      15 /* end of processor specific */

/*
 * Symbol types (ELF32_ST_TYPE)
 */
#define STT_NOTYPE      0  /* symbol type not specified */
#define STT_OBJECT      1  /* associated with data object */
#define STT_FUNC        2  /* associated with function */
#define STT_SECTION     3  /* associated with section */
#define STT_FILE        4  /* associated with source file */
#define STT_LOPROC      13 /* start of processor specific */
#define STT_HIPROC      15 /* end of processor specific */

struct elfParameters
{
  unsigned int virtualFileAddress;
  unsigned int virtualEntryPoint;
  unsigned int entryPoint;
};

struct elfWorkspace
{
  Elf32_Ehdr *ElfHeader;           /* pointer to elf header */
  Elf32_Phdr *ProgramHeader;       /* pointer to program header */
  Elf32_Shdr *SectionTable;        /* pointer to section header table */
  char *StringTable;               /* pointer to string header table */
  char *symbolStringTable;         /* pointer to symbol string table */

  int elfEndian;                   /* endian type of elf file */

  unsigned int virtualFileAddress; /* virtual file address */

  struct symbolWorkspace *symbolWorkspace_p;
};

struct elfSectionInfo
{
  char *name;                          /* section name */
  unsigned int address;                /* section address */
  unsigned int offset;                 /* offset into section */
  unsigned int size;                   /* section size */
};

struct elfSymbolInfo
{
  char *name;
  unsigned int address;
  unsigned int offset;
  unsigned int size;
};

/*
 * This struct is used during a call to traverseSYM, so we
 * can keep track of variables we need when our callback functions
 * are called.
 */
struct elfCallbackParams
{
  struct elfWorkspace *ws;
  void (*printCallback)(void *, const char *, ...);
  void *printCallbackArgs;
  char *str;
  unsigned int address;
};

struct elfFlagsInfo
{
  unsigned int flag; /* flag bitmask */
  char *desc;        /* flag description */
};

/*
 * Check whether addr is between 'ptr' and 'ptr + size'
 */
#define INSIDE_FILE_ELF(ptr, size, addr)                              \
(                                                                     \
  ((unsigned char *)(addr) >= (unsigned char *)(ptr) &&               \
   (unsigned char *)(addr) <= ((unsigned char *)(ptr) + (size)))      \
)

/*
 * Prototypes
 */

struct elfWorkspace *initELF();
void termELF(struct elfWorkspace *ws);
int checkELF(struct elfWorkspace *ws, void *ptr, size_t size,
             struct elfParameters *params, char *str, int platformEndian);
unsigned long loadSymbolsELF(struct elfWorkspace *ws);
void unloadSymbolsELF(struct elfWorkspace *ws);
int findSectionELF(struct elfWorkspace *ws, char *name,
                   unsigned int address, struct elfSectionInfo *secinfo);
int findSymbolELF(struct elfWorkspace *ws, char *name,
                  unsigned int address, struct elfSymbolInfo *syminfo);
void printHeaderELF(struct elfWorkspace *ws,
                    void (*callback)(void *, const char *, ...), void *args);
void printSectionInfoELF(struct elfWorkspace *ws, char *sname,
                         void (*callback)(void *, const char *, ...),
                         void *args);
void printSymbolsELF(struct elfWorkspace *ws, char *symname,
                     void (*callback)(void *, const char *, ...),
                     void *args);

#endif /* INCLUDED_libOFF_fmt_elf_h */
