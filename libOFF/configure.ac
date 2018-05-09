dnl Process this file with autoconf to produce a configure script.
AC_INIT([libOFF], [0.0.5])
AC_CONFIG_SRCDIR([source/libOFF.c])

dnl AC_CONFIG_AUX_DIR(autoconf)
AC_CONFIG_HEADER([include/cfgOFF.h include/api_cfgOFF.h])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

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
