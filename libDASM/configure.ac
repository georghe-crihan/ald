dnl Process this file with autoconf to produce a configure script.
AC_INIT([libDASM], [0.1.2])
AC_CONFIG_SRCDIR([source/disassemble.c])

dnl AC_CONFIG_AUX_DIR(autoconf)
AC_CONFIG_HEADER([include/cfgDASM.h include/api_cfgDASM.h])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

AC_CANONICAL_HOST

case "${host_cpu}" in
changequote(,)
  i[3456]86)
changequote([,])
    arch_frag=ix86
    AC_DEFINE(INTEL86, 1, [Define if you are running an Intel x86 cpu])
    ;;
  *)
    arch_frag=unknown
    ;;
esac

AC_SUBST(arch_frag)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

dnl Check for a suitable install program
AC_PROG_INSTALL

dnl Checks for header files.
AC_HEADER_STDC

dnl Checks for library functions.
AC_TYPE_SIGNAL
AC_CHECK_FUNCS(strdup strerror)
AC_CHECK_FUNCS(vprintf)

AC_OUTPUT(                  \
Makefile                    \
arch/Makefile               \
arch/ix86/Makefile          \
arch/ix86/source/Makefile   \
source/Makefile             \
test/Makefile               \
test/asm/Makefile           \
test/disasm/Makefile        \
test/misc/Makefile          \
)
