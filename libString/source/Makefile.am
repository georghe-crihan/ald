noinst_LIBRARIES = libString.a

libString_a_SOURCES = \
  Snprintf.c          \
  SplitBuffer.c       \
  Strdup.c            \
  Strncasecmp.c       \
  Strncpy.c           \
  alloc.c             \
  version.c

version.o: version.c
	$(COMPILE) -DVERSION=\"${PACKAGE_VERSION}\" -c -o version.o version.c

INCLUDES = -I../include
