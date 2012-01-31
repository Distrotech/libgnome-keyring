/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-keyrings.c: Test basic keyring functionality

   Copyright (C) 2012 Red Hat Inc.

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stefw@gnome.org>
*/

#include "config.h"

#include "gnome-keyring.h"
#include "gkr-misc.h"

#include "mock-service.h"

#include "egg/egg-testing.h"

static void
on_items_found (GnomeKeyringResult result,
                GList *list,
                gpointer data)
{
	GnomeKeyringResult *res = data;
	g_assert_cmpint (result, ==, *res);
	egg_test_wait_stop ();
}

static void
test_immediate (void)
{
	GnomeKeyringAttributeList *attrs;
	GnomeKeyringResult res = GNOME_KEYRING_RESULT_CANCELLED;
	gpointer operation;

	attrs = gnome_keyring_attribute_list_new ();
	gnome_keyring_attribute_list_append_string (attrs, "even", "false");

	operation = gnome_keyring_find_items (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                      attrs, on_items_found, &res, NULL);
	gnome_keyring_attribute_list_free (attrs);

	gnome_keyring_cancel_request (operation);

	egg_test_wait ();
}

static void
test_twice (void)
{
	GnomeKeyringAttributeList *attrs;
	GnomeKeyringResult res = GNOME_KEYRING_RESULT_CANCELLED;
	gpointer operation;

	attrs = gnome_keyring_attribute_list_new ();
	gnome_keyring_attribute_list_append_string (attrs, "even", "false");

	operation = gnome_keyring_find_items (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                      attrs, on_items_found, &res, NULL);
	gnome_keyring_attribute_list_free (attrs);

	gnome_keyring_cancel_request (operation);
	gnome_keyring_cancel_request (operation);

	egg_test_wait ();
}

typedef struct {
	gint which;
	GnomeKeyringResult expect;
	gpointer operation;
	GHashTable *requests;
} Request;

static void
request_free (gpointer data)
{
	g_slice_free (Request, data);
}

static void
on_intense_request (GnomeKeyringResult result,
                    GList *list,
                    gpointer data)
{
	Request *request = data;
	g_assert_cmpint (result, ==, request->expect);
	g_hash_table_remove (request->requests, &request->which);

	if (result == GNOME_KEYRING_RESULT_CANCELLED)
		g_printerr ("!");
	else if (result == GNOME_KEYRING_RESULT_OK)
		g_printerr (".");
	else
		g_printerr ("E");
}

static void
test_intense (void)
{
	#define ITERATIONS 200
	GnomeKeyringAttributeList *attrs;
	Request *request;
	GHashTable *requests;
	GHashTableIter iter;
	gint *lookup;
	gint which;
	gint i = 0;

	attrs = gnome_keyring_attribute_list_new ();
	gnome_keyring_attribute_list_append_string (attrs, "even", "false");

	requests = g_hash_table_new_full (g_int_hash, g_int_equal, NULL, NULL);

	for (;;) {
		if (i++ < ITERATIONS) {
			request = g_slice_new0 (Request);
			request->which = i;
			request->requests = requests;
			request->expect = GNOME_KEYRING_RESULT_OK;
			request->operation = gnome_keyring_find_items (GNOME_KEYRING_ITEM_GENERIC_SECRET,
			                                               attrs, on_intense_request,
			                                               request, request_free);

			g_hash_table_insert (requests, &request->which, request);
			which = g_random_int_range (0, MIN (i, ITERATIONS));

		} else {
			g_hash_table_iter_init (&iter, requests);
			if (!g_hash_table_iter_next (&iter, (gpointer *)&lookup, NULL))
				break;
			which = *lookup;
		}

		egg_test_wait_until (g_random_int_range (2, 50));
		g_printerr (" ");

		request = g_hash_table_lookup (requests, &which);
		if (request != NULL) {
			request->expect = GNOME_KEYRING_RESULT_CANCELLED;
			gnome_keyring_cancel_request (request->operation);
		}
	}

	g_hash_table_destroy (requests);
	gnome_keyring_attribute_list_free (attrs);
}

int
main (int argc, char **argv)
{
	const gchar *address;
	GError *error = NULL;
	const gchar *service;
	int ret = 0;

	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-cancel");

	/* Need to have DBUS running */
	address = g_getenv ("DBUS_SESSION_BUS_ADDRESS");
	if (!address || !address[0]) {
		g_printerr ("no DBus session available, skipping tests.");
		return 0;
	}

	service = g_getenv ("GNOME_KEYRING_TEST_SERVICE");
	if (service && service[0])
		service = NULL;

	g_test_add_func ("/cancel/immediate", test_immediate);
	g_test_add_func ("/cancel/twice", test_twice);
	if (g_test_thorough ())
		g_test_add_func ("/cancel/intense", test_intense);

	if (service) {
		g_printerr ("running tests against secret service: %s", service);
		gkr_service_name = service;

	} else if (!mock_service_start ("mock-service-cancel.py", &error)) {
		g_printerr ("\nCouldn't start mock secret service: %s\n\n", error->message);
		return 1;
	}

	ret = egg_tests_run_with_loop ();

	mock_service_stop ();
	return ret;
}
