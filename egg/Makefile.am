
noinst_LTLIBRARIES = \
	libegg.la

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_builddir)

libegg_la_CFLAGS = \
	$(GLIB_CFLAGS)

libegg_la_SOURCES = \
	egg-unix-credentials.c egg-unix-credentials.h \
	egg-secure-memory.c egg-secure-memory.h

# -------------------------------------------------------------------

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR =
endif

SUBDIRS = . $(TESTS_DIR)
