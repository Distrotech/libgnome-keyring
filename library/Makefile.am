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

PUBLIC_SOURCES = \
	gnome-keyring.c \
	gnome-keyring.h \
	gnome-keyring-memory.h \
	gnome-keyring-memory.c \
	gnome-keyring-result.h \
	gnome-keyring-utils.c

libgnome_keyring_la_SOURCES = \
	gkr-callback.c gkr-callback.h \
	gkr-debug.c gkr-debug.h \
	gkr-misc.c gkr-misc.h \
	gkr-operation.c gkr-operation.h \
	gkr-session.c gkr-session.h \
	gnome-keyring-private.h \
	$(PUBLIC_SOURCES)

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

noinst_LTLIBRARIES = libgnome-keyring-testable.la
libgnome_keyring_testable_la_SOURCES =
libgnome_keyring_testable_la_LIBADD = \
	$(libgnome_keyring_la_OBJECTS) \
	$(libgnome_keyring_la_LIBADD)
libgnome_keyring_testable_la_DEPENDENCIES = $(libgnome_keyring_la_OBJECTS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gnome-keyring-1.pc

EXTRA_DIST = \
	gnome-keyring-1-uninstalled.pc.in \
	GnomeKeyring-1.0.metadata \
	GnomeKeyring-1.0-custom.vala

CLEANFILES=

# build introspection typelib
-include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS = --add-include-path=$(srcdir) --warn-all
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir)

if HAVE_INTROSPECTION
# the gkr-* files are not part of the public API
GnomeKeyring-1.0.gir: $(lib_LTLIBRARIES)
GnomeKeyring_1_0_gir_INCLUDES = GObject-2.0
GnomeKeyring_1_0_gir_CFLAGS = $(INCLUDES)
GnomeKeyring_1_0_gir_LIBS = $(lib_LTLIBRARIES)
GnomeKeyring_1_0_gir_FILES = $(PUBLIC_SOURCES)
GnomeKeyring_1_0_gir_SCANNERFLAGS = --c-include "gnome-keyring.h"
INTROSPECTION_GIRS += GnomeKeyring-1.0.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES += $(gir_DATA) $(typelib_DATA)

if ENABLE_VAPIGEN
-include $(VAPIGEN_MAKEFILE)

gnome-keyring-1.vapi: GnomeKeyring-1.0.gir GnomeKeyring-1.0.metadata GnomeKeyring-1.0-custom.vala

VAPIGEN_VAPIS = gnome-keyring-1.vapi
CLEANFILES += $(VAPIGEN_VAPIS)

gnome_keyring_1_vapi_METADATADIRS = $(srcdir)
gnome_keyring_1_vapi_FILES = GnomeKeyring-1.0.gir $(srcdir)/GnomeKeyring-1.0-custom.vala

vapidir = $(VAPIGEN_VAPIDIR)
vapi_DATA = $(VAPIGEN_VAPIS)
endif
endif

SUBDIRS = . tests
