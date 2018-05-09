noinst_LIBRARIES = libDebug.a

libDebug_a_SOURCES = \
  args.c             \
  break.c            \
  libDebug.c         \
  version.c

version.o: version.c
	$(COMPILE) -DVERSION=\"${PACKAGE_VERSION}\" -c -o version.o version.c

libDebug_a_LIBADD = ../arch/${arch_frag}/source/*.o
