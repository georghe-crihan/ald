dnl Process this file with autoconf to produce a configure script.
AC_INIT([ald], [0.1.7])
AC_CONFIG_SRCDIR([source/main.c])

dnl AC_CONFIG_AUX_DIR(autoconf)
AC_CONFIG_HEADER(include/defs.h)

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

AC_CANONICAL_HOST

dnl case "${host_os}" in
dnl     *openbsd*)
dnl     AC_CHECK_LIB(termcap, tgetent, [LIBS="$LIBS -ltermcap"])
dnl     ;;
dnl esac

CFLAGS="-g -O2"

dnl Checks for programs.
AC_PROG_CC

dnl Check for a suitable install program
AC_PROG_INSTALL

dnl Checks for header files.
AC_HEADER_STDC

AC_PREPROC_IFELSE([termios.h],
                  [AC_DEFINE(HAVE_TERMIOS_H,
                             1,
                             [Define if you have termios.h])])
AC_PREPROC_IFELSE([termio.h],
                  [AC_DEFINE(HAVE_TERMIO_H,
                             1,
                             [Define if you have termio.h])])

AC_PREPROC_IFELSE([readline/readline.h],
                  [AC_DEFINE(HAVE_READLINE_READLINE_H,
                             1,
                             [Define if you have readline/readline.h])])
AC_PREPROC_IFELSE([readline/history.h],
                  [AC_DEFINE(HAVE_READLINE_HISTORY_H,
                             1,
                             [Define if you have readline/history.h])])

AC_PREPROC_IFELSE([stdarg.h],
                  [],
                  [AC_MSG_ERROR(** You must have stdarg.h in order to compile ald **)])

AC_ARG_ENABLE(readline, [  --enable-readline      Enable readline support [default=yes]])

dnl Check for the readline library, which may also depend
dnl on libtermcap

ac_cv_readline_libs=""
if test ! "$enable_readline" = "no"; then
  oldlibs="$LIBS"
  ac_cv_readline_libs="-lreadline"
  LIBS="$oldlibs $ac_cv_readline_libs"
  AC_MSG_CHECKING(for readline)
  AC_TRY_LINK(extern char *readline();,
              char *line=readline();,
              ac_cv_have_readline="yes")
  if test ! "$ac_cv_have_readline" = "yes"; then
    ac_cv_readline_libs="-lreadline -ltermcap"
    LIBS="$oldlibs $ac_cv_readline_libs"
    AC_TRY_LINK(extern char *readline();,
                char *line=readline();,
                ac_cv_have_readline="yes")
  fi
  if test "$ac_cv_have_readline" = "yes"; then
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
  fi
  LIBS="$oldlibs"
fi

if test "$ac_cv_have_readline" = "yes"; then
  AC_DEFINE(HAVE_READLINE, 1, [Define if you have the readline library])
  LIBS="$LIBS $ac_cv_readline_libs"
fi

ac_cv_assert="-DNDEBUG"

AC_ARG_ENABLE(assert,
[
  --enable-assert        Enable assert().
  --disable-assert       Disable assert().
],
[
  case "$enableval" in
    yes)
      ac_cv_assert=""
      ;;
    no)
      ac_cv_assert="-DNDEBUG"
      ;;
  esac
])

if test -n "$ac_cv_assert"; then
  CFLAGS="${CFLAGS} $ac_cv_assert"
fi

AC_HEADER_TIME

dnl Checks for library functions.
AC_TYPE_SIGNAL
AC_CHECK_FUNCS(strdup strerror)
AC_CHECK_FUNCS(vprintf)

case "${host}" in
changequote(,)
  i[3456]86-*)
changequote([,])
    AC_DEFINE(WORDSIZE, 2,
              [Define to number of bytes in one machine word])
    AC_DEFINE(HALFWORD, 1,
              [Define to number of bytes in half a machine word])
    AC_DEFINE(DWORD, 4,
              [Define to number of bytes in two machine words])
    ;;
  *)
    AC_MSG_WARN([[*****************************************************]])
    AC_MSG_WARN([[Unknown word size for this architecture: ${host}]])
    AC_MSG_WARN([[You must define the size (in bytes) of the machine]])
    AC_MSG_WARN([[word in include/defs.h under #define WORDSIZE <value>]])
    AC_MSG_WARN([[*****************************************************]])
    ;;
esac

AC_ARG_ENABLE(gtk, [  --enable-gtk           Enable gtk gui [default=yes]])

dnl if test ! "$enable_gtk" = "no"; then
dnl   AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
dnl   if test x$PKG_CONFIG != xno; then
dnl     GTK_CFLAGS=`$PKG_CONFIG --cflags gtk+-2.0`
dnl     GTK_LIBS=`$PKG_CONFIG --libs gtk+-2.0`
dnl     AC_SUBST(GTK_CFLAGS)
dnl     AC_SUBST(GTK_LIBS)
dnl     enable_gtk="yes"
dnl   else
dnl     enable_gtk="no"
dnl   fi
dnl fi

AC_CONFIG_SUBDIRS(libString)
AC_CONFIG_SUBDIRS(libDebug)
AC_CONFIG_SUBDIRS(libDASM)
AC_CONFIG_SUBDIRS(libOFF)

AC_CONFIG_FILES([                 \
Makefile                          \
doc/Makefile                      \
source/Makefile                   \
ui/gtkgui/Makefile                \
])

AC_OUTPUT

dnl Use sed to grab the version from Makefile.in
dnl VERSION=`sed -n -e 's/VERSION = *\(.*\)$/\1/p' Makefile.in`

echo "
Configuration:

  ald version:                    ${PACKAGE_VERSION}
  Host:                           ${host}
  Install prefix:                 ${prefix}
  Compiler:                       ${CC}
  Compiler Flags:                 ${CFLAGS}"

if test -n "$ac_cv_have_readline"; then
  echo "  Readline support:               enabled"
  echo "  Readline library:               $ac_cv_readline_libs"
else
  echo "  Readline support:               disabled"
fi

if test "$enable_gtk" = "yes"; then
  echo "  GTK gui:                        enabled"
else
  echo "  GTK gui:                        disabled"
fi

echo
echo "ald is now configured for your system. You can run make here."
echo
