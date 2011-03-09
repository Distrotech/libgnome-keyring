
INCLUDES = \
	-I$(top_srcdir)/library \
	$(LIBRARY_CFLAGS)

LDADD =  \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libgnome-keyring.la \
	$(LIBRARY_LIBS)

TEST_PROGS = \
	test-memory \
	test-keyrings \
	test-other \
	test-any-daemon

check_PROGRAMS = \
	test-prompting \
	$(TEST_PROGS)

test: $(TEST_PROGS)
	gtester -k --verbose $(TEST_PROGS)

if WITH_TESTS
all-local: $(check_PROGRAMS)
endif

check-local: test
