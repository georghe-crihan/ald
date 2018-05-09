# libOFF/source/Makefile.am
# $Id: Makefile.am,v 1.3 2004/10/10 16:06:07 pa33 Exp $

noinst_LIBRARIES = libOFF.a

libOFF_a_SOURCES = \
  fmt_aout.c       \
  fmt_elf.c        \
  libOFF.c         \
  symbols.c        \
  version.c

version.o: version.c
	$(COMPILE) -DVERSION=\"${PACKAGE_VERSION}\" -c -o version.o version.c
