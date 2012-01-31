
INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/library \
	-DSRCDIR="\"@abs_srcdir@\"" \
	$(LIBRARY_CFLAGS)

noinst_LTLIBRARIES = libmock-service.la

libmock_service_la_SOURCES = \
	mock-service.c mock-service.h \
	$(NULL)

libmock_service_la_CFLAGS = \
	$(LIBGCRYPT_CFLAGS)

libmock_service_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libgnome-keyring-testable.la \
	$(LIBGCRYPT_LIBS)

LDADD =  \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libgnome-keyring-testable.la \
	libmock-service.la \
	$(LIBRARY_LIBS)

TEST_PROGS = \
	test-memory \
	test-keyrings \
	test-cancel \
	test-other

check_PROGRAMS = \
	test-prompting \
	$(TEST_PROGS)

noinst_PROGRAMS = \
	frob-any-daemon \
	frob-unlock-keyring \
	frob-list-modified \
	frob-default-keyring

EXTRA_DIST = \
	test-gi.py \
	mock \
	mock-service-normal.py \
	mock-service-cancel.py

test: $(TEST_PROGS)
	gtester -k --verbose $(TEST_PROGS)

all-local: $(check_PROGRAMS)

check-local: test
