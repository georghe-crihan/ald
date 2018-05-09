# Assembly Language Debugger
# ./source Makefile.am (C) Patrick Alken 2000-2004
# $Id: Makefile.am,v 1.3 2004/10/10 05:29:50 pa33 Exp $

bin_PROGRAMS = ald

ald_SOURCES =              \
  c_attach.c               \
  c_break.c                \
  c_continue.c             \
  c_dbreak.c               \
  c_detach.c               \
  c_disable.c              \
  c_disassemble.c          \
  c_display.c              \
  c_enable.c               \
  c_enter.c                \
  c_examine.c              \
  c_file.c                 \
  c_help.c                 \
  c_ignore.c               \
  c_lbreak.c               \
  c_ldisplay.c             \
  c_load.c                 \
  c_next.c                 \
  c_quit.c                 \
  c_register.c             \
  c_run.c                  \
  c_set.c                  \
  c_step.c                 \
  c_tbreak.c               \
  c_undisplay.c            \
  c_unload.c               \
  callback.c               \
  command.c                \
  disassemble.c            \
  display.c                \
  help.c                   \
  input.c                  \
  list.c                   \
  load.c                   \
  main.c                   \
  memory.c                 \
  misc.c                   \
  output.c                 \
  print.c                  \
  rc.c                     \
  readln.c                 \
  registers.c              \
  set.c                    \
  signals.c                \
  terminal.c               \
  traceresult.c            \
  version.c

version.o: version.c
	$(COMPILE) -DVERSION=\"$(PACKAGE_VERSION)\" -c -o version.o version.c

INCLUDES = -I../include -I../libDebug/include -I../libDASM/include -I../libOFF/include -I../libString/include

ald_LDADD =                       \
  ../libDebug/source/libDebug.a   \
  ../libDASM/source/libDASM.a     \
  ../libOFF/source/libOFF.a       \
  ../libString/source/libString.a
