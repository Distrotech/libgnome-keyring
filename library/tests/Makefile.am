
TEST_AUTO = \
	test-memory.c \
	test-keyrings.c \
	test-other.c

TEST_LIBS = \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libgnome-keyring.la

include $(top_srcdir)/tests/gtest.make

# ------------------------------------------------------------------

noinst_PROGRAMS += \
	test-prompting

test_prompting_SOURCES = \
	test-prompting.c

test_prompting_CFLAGS = \
	$(GLIB_CFLAGS)

test_prompting_LDADD = \
	$(top_builddir)/library/libgnome-keyring.la \
	$(GLIB_LIBS)
