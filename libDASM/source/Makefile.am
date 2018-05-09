noinst_LIBRARIES = libDASM.a

libDASM_a_SOURCES = \
  assemble.c        \
  disassemble.c     \
  libDASM.c         \
  version.c

version.o: version.c
	$(COMPILE) -DVERSION=\"${PACKAGE_VERSION}\" -c -o version.o version.c

libDASM_a_LIBADD = ../arch/${arch_frag}/source/*.o
