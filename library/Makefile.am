libgnomekeyringincludedir = $(includedir)/gnome-keyring-1/

lib_LTLIBRARIES=libgnome-keyring.la

INCLUDES= \
	-DPREFIX=\""$(prefix)"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\" \
	-DG_LOG_DOMAIN=\""Gkr"\" \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(LIBRARY_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

libgnome_keyring_la_SOURCES = \
	gkr-callback.c gkr-callback.h \
	gkr-debug.c gkr-debug.h \
	gkr-misc.c gkr-misc.h \
	gkr-operation.c gkr-operation.h \
	gkr-session.c gkr-session.h \
	gnome-keyring.c \
	gnome-keyring.h \
	gnome-keyring-memory.h \
	gnome-keyring-memory.c \
	gnome-keyring-private.h \
	gnome-keyring-result.h \
	gnome-keyring-utils.c

libgnomekeyringinclude_HEADERS = \
	gnome-keyring.h \
	gnome-keyring-memory.h \
	gnome-keyring-result.h

libgnome_keyring_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(LIBRARY_LIBS) \
	$(LIBGCRYPT_LIBS)

libgnome_keyring_la_LDFLAGS = \
	-version-info $(LIB_GNOME_KEYRING_LT_VERSION) \
	-no-undefined -export-symbols-regex 'gnome_keyring_|GNOME_KEYRING_'

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gnome-keyring-1.pc

EXTRA_DIST = \
	gnome-keyring-1-uninstalled.pc.in

CLEANFILES=

# build introspection typelib
-include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS = --add-include-path=$(srcdir) --warn-all
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir)

if HAVE_INTROSPECTION
# the gkr-* files are not part of the public API
introspection_sources = $(filter-out gkr-% %-private.h,$(libgnome_keyring_la_SOURCES))

GnomeKeyring-1.0.gir: $(lib_LTLIBRARIES)
GnomeKeyring_1_0_gir_INCLUDES = GObject-2.0
GnomeKeyring_1_0_gir_CFLAGS = $(INCLUDES)
GnomeKeyring_1_0_gir_LIBS = $(lib_LTLIBRARIES)
GnomeKeyring_1_0_gir_FILES = $(introspection_sources)
INTROSPECTION_GIRS += GnomeKeyring-1.0.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES += $(gir_DATA) $(typelib_DATA)
endif

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR =
endif

SUBDIRS = . \
	$(TESTS_DIR)
