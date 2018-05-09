dnl Process this file with autoconf to produce a configure script.
AC_INIT([libOFF], [1.16])
AC_CONFIG_SRCDIR([source/libOFF.c])

dnl AC_CONFIG_AUX_DIR(autoconf)
AC_CONFIG_HEADER([include/cfgOFF.h include/api_cfgOFF.h])

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
  darwin*)
    os_makefile_frag="darwin-${text_frag}"
    AC_DEFINE(OS_DARWIN, 1, [Define if you are running Darwin])
    HAVE_MACHO=yes
    ;;
  *)
    os_makefile_frag=unknown
    ;;
esac

AM_CONDITIONAL([HAVE_MACHO], [test x$HAVE_MACHO = xyes])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

dnl Checks for header files.
AC_HEADER_STDC

dnl Checks for library functions.
AC_TYPE_SIGNAL
AC_CHECK_FUNCS(strdup strerror)
AC_CHECK_FUNCS(vprintf)

dnl Check for types
AC_CHECK_TYPE(uint8_t, unsigned char)
AC_CHECK_TYPE(uint16_t, unsigned short)
AC_CHECK_TYPE(uint32_t, unsigned int)
AC_CHECK_TYPE(uint64_t, unsigned long)

AC_OUTPUT(                  \
Makefile                    \
source/Makefile             \
test/Makefile               \
)
