dnl Process this file with autoconf to produce a configure script.
AC_INIT([libDebug], [0.1.1])
AC_CONFIG_SRCDIR([source/libDebug.c])

dnl AC_CONFIG_AUX_DIR(autoconf)
AC_CONFIG_HEADERS([include/cfgDebug.h include/api_cfgDebug.h])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

AC_CANONICAL_HOST

case "${host_cpu}" in
changequote(,)
  i[3456]86)
changequote([,])
    arch_frag=ix86
    text_frag=x86
    ;;
  *)
    arch_frag=unknown
    ;;
esac

AC_SUBST(arch_frag)

case "${host_os}" in
  *freebsd*)
    os_makefile_frag="freebsd-${text_frag}"
    AC_DEFINE(OS_FREEBSD, 1, [Define if you are running FreeBSD])
    AC_DEFINE(OS_BSD, 1, [Define if you are running *BSD])
    ;;
  *netbsd*)
    os_makefile_frag="netbsd-${text_frag}"
    AC_DEFINE(OS_NETBSD, 1, [Define if you are running NetBSD])
    AC_DEFINE(OS_BSD, 1, [Define if you are running *BSD])
    ;;
  *openbsd*)
    os_makefile_frag="openbsd-${text_frag}"
    AC_DEFINE(OS_OPENBSD, 1, [Define if you are running OpenBSD])
    AC_DEFINE(OS_BSD, 1, [Define if you are running *BSD])
    ;;
  *linux*)
    os_makefile_frag="linux-${text_frag}"
    AC_DEFINE(OS_LINUX, 1, [Define if you are running Linux])
    ;;
  *)
    os_makefile_frag=unknown
    ;;
esac

AC_SUBST(os_makefile_frag)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

dnl Checks for header files.
AC_HEADER_STDC

# Check for PTRACE_GETFPXREGS - got this from gdb
AC_MSG_CHECKING(for PTRACE_GETFPXREGS)
AC_CACHE_VAL(ald_cv_have_ptrace_getfpxregs,
             [AC_TRY_COMPILE([#include <asm/ptrace.h>],
                             [PTRACE_GETFPXREGS;],
                             [ald_cv_have_ptrace_getfpxregs=yes],
                             [ald_cv_have_ptrace_getfpxregs=no])
             ])
AC_MSG_RESULT($ald_cv_have_ptrace_getfpxregs)
if test $ald_cv_have_ptrace_getfpxregs = yes; then
  AC_DEFINE(HAVE_PTRACE_GETFPXREGS, 1, [Define if you have PTRACE_GETFPXREGS])
fi

dnl Make a symbolic link from the operating system specific file
dnl to the os-${text_frag} file which the local Makefile will then
dnl compile

ln -sf ${os_makefile_frag}.c ./arch/${arch_frag}/source/os-${text_frag}.c

AC_OUTPUT(                        \
Makefile                          \
arch/Makefile                     \
arch/ix86/Makefile                \
arch/ix86/source/Makefile         \
source/Makefile                   \
)
