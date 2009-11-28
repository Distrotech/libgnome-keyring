/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring.c - library for talking to the keyring daemon.

   Copyright (C) 2003 Red Hat, Inc
   Copyright (C) 2007 Stefan Walter

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

   Author: Alexander Larsson <alexl@redhat.com>
   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gnome-keyring.h"
#include "gnome-keyring-memory.h"
#include "gnome-keyring-private.h"

#include "egg/egg-dbus.h"

#include <dbus/dbus.h>

#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdarg.h>

#define BROKEN                         GNOME_KEYRING_RESULT_IO_ERROR

#define SECRETS_SERVICE                "org.freedesktop.secrets"
#define SERVICE_PATH                   "/org/freedesktop/secrets"
#define COLLECTION_INTERFACE           "org.freedesktop.Secrets.Collection"
#define ITEM_INTERFACE                 "org.freedesktop.Secrets.Item"
#define PROMPT_INTERFACE               "org.freedesktop.Secrets.Prompt"
#define SERVICE_INTERFACE              "org.freedesktop.Secrets.Service"
#define COLLECTION_PREFIX              "/org/freedesktop/secrets/collection/"
#define COLLECTION_DEFAULT             "/org/freedesktop/secrets/collection/default"

/**
 * SECTION:gnome-keyring-generic-callbacks
 * @title: Callbacks
 * @short_description: Different callbacks for retrieving async results
 */

typedef enum {
	CALLBACK_DONE,
	CALLBACK_GET_STRING,
	CALLBACK_GET_INT,
	CALLBACK_GET_LIST,
	CALLBACK_GET_KEYRING_INFO,
	CALLBACK_GET_ITEM_INFO,
	CALLBACK_GET_ATTRIBUTES,
	CALLBACK_GET_ACL
} KeyringCallbackType;

typedef GnomeKeyringResult (*ParseIterFunc) (DBusMessageIter *iter, gpointer user_data);

#define NORMAL_ALLOCATOR  ((EggBufferAllocator)g_realloc)
#define SECURE_ALLOCATOR  ((EggBufferAllocator)gnome_keyring_memory_realloc)
#define INCOMPLETE -1

static DBusConnection *dbus_connection = NULL;
G_LOCK_DEFINE_STATIC(dbus_connection);

typedef struct _Operation Operation;
typedef void (*KeyringHandleReply) (Operation *op, DBusMessage *reply);

struct _Operation {
	/* First two only atomically accessed */
	gint refs;
	gint result;

	/* Managed by operation calls */
	DBusConnection *conn;
	DBusPendingCall *pending;
	gchar *prompt;

	/* User callback information */
	KeyringCallbackType user_callback_type;
	gpointer user_callback;
	gpointer user_data;
	GDestroyNotify destroy_user_data;

	/* May be set by others */
	KeyringHandleReply reply_handler;
	gpointer reply_data;
	GDestroyNotify destroy_reply_data;
};

static Operation*
operation_ref (gpointer data)
{
	Operation *op = data;
	g_return_val_if_fail (op, NULL);
	g_atomic_int_inc (&op->refs);
	return op;
}

static void
operation_unref (gpointer data)
{
	Operation *op = data;

	if (!op)
		return;

	if (!g_atomic_int_dec_and_test (&op->refs))
		return;

	if (op->pending) {
		dbus_pending_call_cancel (op->pending);
		dbus_pending_call_unref (op->pending);
		op->pending = NULL;
	}
	if (op->destroy_user_data != NULL && op->user_data != NULL)
		(*op->destroy_user_data) (op->user_data);
	if (op->destroy_reply_data != NULL && op->reply_data != NULL)
		(*op->destroy_reply_data) (op->reply_data);
	g_free (op->prompt);
	g_free (op);
}

static Operation*
operation_new (gpointer callback, KeyringCallbackType callback_type,
               gpointer user_data, GDestroyNotify destroy_user_data)
{
	Operation *op;

	op = g_new0 (Operation, 1);

	op->refs = 1;
	op->result = INCOMPLETE;
	op->user_callback_type = callback_type;
	op->user_callback = callback;
	op->user_data = user_data;
	op->destroy_user_data = destroy_user_data;

	return op;
}

static GnomeKeyringResult
operation_get_result (Operation *op)
{
	GnomeKeyringResult res;
	g_assert (op);
	res = g_atomic_int_get (&op->result);
	g_assert (res != INCOMPLETE);
	return res;
}

static gboolean
operation_set_result (Operation *op, GnomeKeyringResult res)
{
	g_assert (op);
	g_assert (res != INCOMPLETE);
	return g_atomic_int_compare_and_exchange (&op->result, INCOMPLETE, res);
}

static void
operation_complete (Operation *op, GnomeKeyringResult res)
{
	g_assert (op);
	switch (op->user_callback_type) {
	case CALLBACK_DONE:
		((GnomeKeyringOperationDoneCallback)op->user_callback) (res, op->user_data);
		break;
	case CALLBACK_GET_STRING:
		((GnomeKeyringOperationGetStringCallback)op->user_callback) (res, NULL, op->user_data);
		break;
	case CALLBACK_GET_INT:
		((GnomeKeyringOperationGetIntCallback)op->user_callback) (res, 0, op->user_data);
		break;
	case CALLBACK_GET_LIST:
		((GnomeKeyringOperationGetListCallback)op->user_callback) (res, NULL, op->user_data);
		break;
	case CALLBACK_GET_KEYRING_INFO:
		((GnomeKeyringOperationGetKeyringInfoCallback)op->user_callback) (res, NULL, op->user_data);
		break;
	case CALLBACK_GET_ITEM_INFO:
		((GnomeKeyringOperationGetItemInfoCallback)op->user_callback) (res, NULL, op->user_data);
		break;
	case CALLBACK_GET_ATTRIBUTES:
		((GnomeKeyringOperationGetAttributesCallback)op->user_callback) (res, NULL, op->user_data);
		break;
	case CALLBACK_GET_ACL:
		((GnomeKeyringOperationGetListCallback)op->user_callback) (res, NULL, op->user_data);
		break;
	}
}

static gboolean
on_scheduled_complete (gpointer data)
{
	Operation *op = data;
	operation_complete (op, operation_get_result (op));

	/* Don't run idle handler again */
	return FALSE;
}

static void
operation_schedule_completed (Operation *op, GnomeKeyringResult result)
{
	if (operation_set_result (op, result))
		g_idle_add_full (G_PRIORITY_DEFAULT_IDLE, on_scheduled_complete,
		                 operation_ref (op), operation_unref);
}

static DBusConnection*
connect_to_bus (void)
{
	DBusError derr = DBUS_ERROR_INIT;
	DBusConnection *conn;
	const gchar *rule;

	/*
	 * TODO: We currently really have no way to close this connection or do
	 * cleanup, and it's unclear how and whether we need to.
	 */

	if (!dbus_connection) {
		if (!g_getenv ("DBUS_SESSION_BUS_ADDRESS"))
			return NULL;

		conn = dbus_bus_get_private (DBUS_BUS_SESSION, &derr);
		if (conn == NULL) {
			g_message ("couldn't connect to dbus session bus: %s", derr.message);
			dbus_error_free (&derr);
			return NULL;
		}

		dbus_connection_set_exit_on_disconnect (conn, FALSE);

		/* Listen for the completed signal */
		rule = "type='signal',interface='org.gnome.secrets.Prompt',member='Completed'";
		dbus_bus_add_match (conn, rule, NULL);

		G_LOCK (dbus_connection);
		{
			if (dbus_connection) {
				dbus_connection_unref (dbus_connection);
			} else {
				egg_dbus_connect_with_mainloop (conn, NULL);
				dbus_connection = conn;
			}
		}
	}

	return dbus_connection_ref (dbus_connection);
}

static GnomeKeyringResult
handle_error_to_result (DBusError *derr, const gchar *desc)
{
	g_assert (derr);
	g_assert (dbus_error_is_set (derr));

	if (!desc)
		desc = "secrets service operation failed";

	g_message ("%s: %s", desc, derr->message);
	dbus_error_free (derr);

	/* TODO: Need to be more specific about errors */
	return GNOME_KEYRING_RESULT_IO_ERROR;
}

static DBusHandlerResult
on_prompt_completed (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	Operation *op = user_data;

	g_assert (op);
	g_return_val_if_fail (op->prompt, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_is_signal (message, PROMPT_INTERFACE, "Completed") &&
	    dbus_message_has_path (message, op->prompt)) {

		g_free (op->prompt);
		op->prompt = NULL;
		dbus_connection_remove_filter (op->conn, on_prompt_completed, op);

		if (operation_get_result (op) == INCOMPLETE) {
			if (op->reply_handler)
				(op->reply_handler) (op, message);
		}

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void
on_pending_call_notify (DBusPendingCall *pending, void *user_data)
{
	DBusError derr = DBUS_ERROR_INIT;
	Operation *op = user_data;
	GnomeKeyringResult res;
	DBusMessage *reply;

	g_assert (pending == op->pending);

	reply = dbus_pending_call_steal_reply (pending);
	g_return_if_fail (reply);

	dbus_pending_call_unref (op->pending);
	op->pending = NULL;

	if (dbus_set_error_from_message (&derr, reply)) {

		/* Are we prompting, if so cancel the completed */
		if (op->prompt) {
			g_free (op->prompt);
			op->prompt = NULL;
			dbus_connection_remove_filter (op->conn, on_prompt_completed, op);
		}

		/* Return the error result to the callback */
		res = handle_error_to_result (&derr, NULL);
		g_assert (res != GNOME_KEYRING_RESULT_OK);
		if (operation_set_result (op, res))
			operation_complete (op, res);
	} else {

		/*
		 * Are we prompting not prompting, mark as a reply.
		 * When prompting, completed listener will handle reply.
		 */
		if (!op->prompt && operation_get_result (op) == INCOMPLETE) {
			if (op->reply_handler)
				(op->reply_handler) (op, reply);
		}
	}

	dbus_message_unref (reply);
}

static void
start_operation (Operation *op, DBusMessage *request)
{
	g_assert (op);

	if (!op->conn)
		op->conn = connect_to_bus ();

	if (op->conn) {
		if (!dbus_connection_send_with_reply (op->conn, request, &op->pending, -1))
			g_return_if_reached ();
	}

	if (op->pending)
		dbus_pending_call_set_notify (op->pending, on_pending_call_notify,
		                              operation_ref (op), operation_unref);
	else
		operation_schedule_completed (op, GNOME_KEYRING_RESULT_IO_ERROR);
}

static void
prompt_operation (Operation *op, const gchar *prompt)
{
	DBusMessage *req;

	g_assert (op != NULL);
	g_assert (prompt != NULL);

	/* Start waiting for a completed response to this prompt */
	op->prompt = g_strdup (prompt);
	dbus_connection_add_filter (op->conn, on_prompt_completed,
	                            operation_ref (op), operation_unref);

	req = dbus_message_new_method_call (SECRETS_SERVICE, prompt,
	                                    PROMPT_INTERFACE, "Prompt");

	start_operation (op, req);
	dbus_message_unref (req);
}

static GnomeKeyringResult
send_to_service_and_simple_block (DBusMessage *req, DBusMessage **reply)
{
	DBusConnection *conn;
	DBusError derr = DBUS_ERROR_INIT;
	GnomeKeyringResult res;

	g_assert (req);
	g_assert (reply);

	conn = connect_to_bus ();
	if (conn == NULL) {
		*reply = NULL;
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}

	/* TODO: Timeout here needs to be clarified */
	*reply = dbus_connection_send_with_reply_and_block (conn, req, -1, &derr);
	if (*reply == NULL)
		res = handle_error_to_result (&derr, "couldn't communicate with daemon");
	else
		res = GNOME_KEYRING_RESULT_OK;

	dbus_connection_unref (conn);
	return res;
}

typedef struct _BlockingPrompt {
	const gchar *prompt;
	DBusMessage **signal;
} BlockingPrompt;

static DBusHandlerResult
on_blocking_prompt_completed (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	BlockingPrompt *cp = user_data;

	g_assert (cp->signal);
	g_assert (cp->prompt);

	if (dbus_message_is_signal (message, PROMPT_INTERFACE, "Completed") &&
	    dbus_message_has_path (message, cp->prompt)) {
		g_return_val_if_fail (*cp->signal == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
		*cp->signal = dbus_message_ref (message);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static GnomeKeyringResult
prompt_service_and_block (const gchar *prompt, DBusMessage **reply)
{
	DBusError derr = DBUS_ERROR_INIT;
	DBusMessage *req, *rep, *signal;
	DBusConnection *conn;
	BlockingPrompt cp = { prompt, &signal };
	GnomeKeyringResult res;
	DBusMessageIter iter;
	dbus_bool_t dismissed;

	g_assert (prompt);
	g_assert (reply);

	conn = connect_to_bus ();
	if (conn == NULL) {
		*reply = NULL;
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}

	/* Start waiting for a completed response to this prompt */
	dbus_connection_add_filter (conn, on_blocking_prompt_completed, &cp, NULL);

	req = dbus_message_new_method_call (SECRETS_SERVICE, prompt,
	                                    PROMPT_INTERFACE, "Prompt");

	rep = dbus_connection_send_with_reply_and_block (conn, req, -1, &derr);
	dbus_message_unref (req);
	dbus_message_unref (rep);

	/* Wait for a completed signal */
	if (rep != NULL) {
		dbus_connection_flush (conn);
		while (signal == NULL) {
			if (!dbus_connection_read_write_dispatch (conn, -1))
				break;
		}
	}

	dbus_connection_remove_filter (conn, on_blocking_prompt_completed, &cp);
	dbus_connection_unref (conn);

	/* The prompt method failed for some reason */
	if (rep == NULL) {
		res = handle_error_to_result (&derr, "couldn't perform prompting");

	} else if (signal == NULL) {
		g_message ("the dbus connection disconnected while prompting");
		res = GNOME_KEYRING_RESULT_IO_ERROR;

	} else if (!dbus_message_has_signature (signal, "bv")) {
		g_message ("the Completed signal while prompting had an invalid signature");
		res = GNOME_KEYRING_RESULT_IO_ERROR;

	} else {
		if (!dbus_message_iter_init (signal, &iter) ||
		    dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_BOOLEAN)
			g_return_val_if_reached (BROKEN);
		dbus_message_iter_get_basic (&iter, &dismissed);
		res = dismissed ? GNOME_KEYRING_RESULT_CANCELLED : GNOME_KEYRING_RESULT_OK;
	}

	if (res == GNOME_KEYRING_RESULT_OK) {
		dbus_message_unref (signal);
		*reply = NULL;
	} else {
		*reply = signal;
	}

	return res;
}


static DBusMessage*
prepare_property_get (const gchar *path, const gchar *interface, const gchar *name)
{
	DBusMessage *req;

	g_assert (path);
	g_assert (name);

	if (!interface)
		interface = "";

	req = dbus_message_new_method_call (SECRETS_SERVICE, path,
	                                    DBUS_INTERFACE_PROPERTIES, "Get");
	g_return_val_if_fail (req, NULL);
	if (!dbus_message_append_args (req, DBUS_TYPE_STRING, &interface,
	                               DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
		g_return_val_if_reached (NULL);

	return req;
}

static DBusMessage*
prepare_property_getall (const gchar *path, const gchar *interface)
{
	DBusMessage *req;

	g_assert (path);

	if (!interface)
		interface = "";

	req = dbus_message_new_method_call (SECRETS_SERVICE, path,
	                                    DBUS_INTERFACE_PROPERTIES, "GetAll");
	g_return_val_if_fail (req, NULL);
	if (!dbus_message_append_args (req, DBUS_TYPE_STRING, &interface,
	                               DBUS_TYPE_INVALID))
		g_return_val_if_reached (NULL);

	return req;
}

static void
encode_object_identifier (GString *string, const gchar* name, gssize length)
{
	g_assert (name);

	if (length < 0)
		length = strlen (name);

	while (length > 0) {
		char ch = *(name++);
		--length;

		/* Normal characters can go right through */
		if (G_LIKELY ((ch >= 'A' && ch <= 'Z') ||
		              (ch >= 'a' && ch <= 'z') ||
		              (ch >= '0' && ch <= '9'))) {
			g_string_append_c_inline (string, ch);

		/* Special characters are encoded with a _ */
		} else {
			g_string_append_printf (string, "_%02x", (unsigned int)ch);
		}
	}
}

static void
encode_keyring_string (GString *string, const gchar *keyring)
{
	if (!keyring) {
		g_string_append (string, COLLECTION_DEFAULT);
	} else {
		g_string_append (string, COLLECTION_PREFIX);
		encode_object_identifier (string, keyring, -1);
	}
}

static gchar*
encode_keyring_name (const gchar *keyring)
{
	GString *result = g_string_sized_new (128);
	encode_keyring_string (result, keyring);
	return g_string_free (result, FALSE);
}

static gchar*
encode_keyring_item_id (const gchar *keyring, guint32 id)
{
	GString *result = g_string_sized_new (128);
	encode_keyring_string (result, keyring);
	g_string_append_c (result, '/');
	g_string_append_printf (result, "%lu", (unsigned long)id);
	return g_string_free (result, FALSE);
}

static gchar*
decode_object_identifier (const gchar* enc, gssize length)
{
	GString *result;

	g_assert (enc);

	if (length < 0)
		length = strlen (enc);

	result = g_string_sized_new (length);
	while (length > 0) {
		char ch = *(enc++);
		--length;

		/* Underscores get special handling */
		if (G_UNLIKELY (ch == '_' &&
		                g_ascii_isxdigit(enc[0]) &&
		                g_ascii_isxdigit (enc[1]))) {
			ch = (g_ascii_xdigit_value (enc[0]) * 16) +
			     (g_ascii_xdigit_value (enc[1]));
			enc += 2;
			length -= 2;
		}

		g_string_append_c_inline (result, ch);
	}

	return g_string_free (result, FALSE);
}

static gchar*
decode_keyring_name (const char *path)
{
	gchar *result;

	g_return_val_if_fail (path, NULL);

	if (!g_str_has_prefix (path, COLLECTION_PREFIX)) {
		g_message ("response from daemon contained an bad collection path: %s", path);
		return NULL;
	}

	path += strlen (COLLECTION_PREFIX);
	result = decode_object_identifier (path, -1);
	if (result == NULL) {
		g_message ("response from daemon contained an bad collection path: %s", path);
		return NULL;
	}

	return result;
}

static gboolean
decode_item_id (const char *path, guint32 *id)
{
	const gchar *part;
	gchar *end;

	g_return_val_if_fail (path, FALSE);
	g_assert (id);

	part = strchr (path, '/');
	if (part == NULL || part[1] == '\0') {
		g_message ("response from daemon contained a bad item path: %s", path);
		return FALSE;
	}

	*id = strtoul (part, &end, 10);
	if (!end || end[0] != '\0') {
		g_message ("item has unsupported non-mumeric item identifier: %s", path);
		return FALSE;
	}

	return TRUE;
}

typedef gboolean (*DecodeCallback) (DBusMessageIter *, gpointer);
typedef gboolean (*DecodeDictCallback) (const gchar *, DBusMessageIter *, gpointer);

static GnomeKeyringResult
decode_invalid_response (DBusMessage *reply)
{
	g_assert (reply);
	g_message ("call to daemon returned an invalid response: %s.%s()",
	           dbus_message_get_interface (reply),
	           dbus_message_get_member (reply));
	return GNOME_KEYRING_RESULT_IO_ERROR;
}

static GnomeKeyringResult
decode_property_variant_array (DBusMessage *reply, DecodeCallback callback,
                               gpointer user_data)
{
	DBusMessageIter iter, variant, array;
	int type;

	g_assert (reply);
	g_assert (callback);

	if (dbus_message_has_signature (reply, "v"))
		return decode_invalid_response (reply);

	/* Iter to the variant */
	if (!dbus_message_iter_init (reply, &iter))
		g_return_val_if_reached (BROKEN);
	g_return_val_if_fail (dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_VARIANT, BROKEN);
	dbus_message_iter_recurse (&iter, &variant);

	/* Iter to the array */
	if (dbus_message_iter_get_arg_type (&variant) != DBUS_TYPE_ARRAY)
		return decode_invalid_response (reply);
	dbus_message_iter_recurse (&variant, &array);

	/* Each item in the array */
	for (;;) {
		type = dbus_message_iter_get_arg_type (&array);
		if (type == DBUS_TYPE_INVALID)
			break;
		if (!(callback) (&array, user_data))
			return decode_invalid_response (reply);

		dbus_message_iter_next (&array);
	}

	return GNOME_KEYRING_RESULT_OK;
}

static GnomeKeyringResult
decode_property_dict (DBusMessage *reply, DecodeDictCallback callback,
                      gpointer user_data)
{
	DBusMessageIter iter, variant, array, dict;
	const char *property;
	int type;

	g_assert (reply);
	g_assert (callback);

	if (dbus_message_has_signature (reply, "{sv}"))
		return decode_invalid_response (reply);

	/* Iter to the array */
	if (!dbus_message_iter_init (reply, &iter))
		g_return_val_if_reached (BROKEN);
	g_return_val_if_fail (dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_ARRAY, BROKEN);
	dbus_message_iter_recurse (&iter, &array);

	/* Each dict entry in the array */
	for (;;) {
		type = dbus_message_iter_get_arg_type (&array);
		if (type == DBUS_TYPE_INVALID)
			break;
		g_return_val_if_fail (type != DBUS_TYPE_DICT_ENTRY, BROKEN);

		dbus_message_iter_recurse (&array, &dict);

		/* The property type */
		g_return_val_if_fail (dbus_message_iter_get_arg_type (&dict) != DBUS_TYPE_STRING, BROKEN);
		dbus_message_iter_get_basic (&dict, &property);
		g_return_val_if_fail (property, BROKEN);

		/* The variant value */
		if (!dbus_message_iter_next (&dict))
			g_return_val_if_reached (BROKEN);
		g_return_val_if_fail (dbus_message_iter_get_arg_type (&dict) != DBUS_TYPE_VARIANT, BROKEN);
		dbus_message_iter_recurse (&dict, &variant);

		if (!(callback) (property, &variant, user_data))
			return decode_invalid_response (reply);

		dbus_message_iter_next (&array);
	}

	return GNOME_KEYRING_RESULT_OK;
}

/**
 * SECTION:gnome-keyring-misc
 * @title: Miscellaneous Functions
 * @short_description: Miscellaneous functions.
 **/

/**
 * gnome_keyring_is_available:
 *
 * Check whether you can communicate with a gnome-keyring-daemon.
 *
 * Return value: %FALSE if you can't communicate with the daemon (so you
 * can't load and save passwords).
 **/
gboolean
gnome_keyring_is_available (void)
{
	DBusConnection *conn;
	DBusMessage *req, *reply;

	conn = connect_to_bus ();
	if (conn == NULL)
		return FALSE;

	req = dbus_message_new_method_call (SECRETS_SERVICE, SERVICE_PATH,
	                                    DBUS_INTERFACE_PEER, "Ping");
	g_return_val_if_fail (req, FALSE);

	reply = dbus_connection_send_with_reply_and_block (conn, req, 1000, NULL);
	dbus_message_unref (req);
	dbus_message_unref (reply);
	dbus_connection_unref (conn);

	return (reply != NULL);
}

/**
 * gnome_keyring_cancel_request:
 * @request: The request returned from the asynchronous call function.
 *
 * Cancel an asynchronous request.
 *
 * If a callback was registered when making the asynchronous request, that callback
 * function will be called with a result of %GNOME_KEYRING_RESULT_CANCELLED
 **/
void
gnome_keyring_cancel_request (gpointer request)
{
	Operation *op = request;
	g_return_if_fail (request);
	operation_schedule_completed (op, GNOME_KEYRING_RESULT_CANCELLED);
}

static void
standard_reply (Operation *op, DBusMessage *reply)
{
	GnomeKeyringOperationDoneCallback callback;
	g_assert (op->user_callback_type == CALLBACK_DONE);
	callback = op->user_callback;
	(*callback) (GNOME_KEYRING_RESULT_OK, op->user_data);
}

#if 0
static gboolean
string_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetStringCallback callback;
	char *string;

	g_assert (op->user_callback_type == CALLBACK_GET_STRING);

	callback = op->user_callback;

	if (!gkr_proto_decode_result_string_reply (&op->receive_buffer, &result, &string)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, string, op->user_data);
		g_free (string);
	}

	/* Operation is done */
	return TRUE;
}

static gboolean
int_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetIntCallback callback;
	guint32 integer;

	g_assert (op->user_callback_type == CALLBACK_GET_INT);

	callback = op->user_callback;

	if (!gkr_proto_decode_result_integer_reply (&op->receive_buffer, &result, &integer)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, 0, op->user_data);
	} else {
		(*callback) (result, integer, op->user_data);
	}

	/* Operation is done */
	return TRUE;
}
#endif

/**
 * SECTION:gnome-keyring-keyrings
 * @title: Keyrings
 * @short_description: Listing and managing keyrings
 *
 * %gnome-keyring-daemon manages multiple keyrings. Each keyring can store one or more items containing secrets.
 *
 * One of the keyrings is the default keyring, which can in many cases be used by specifying %NULL for a keyring name.
 *
 * Each keyring can be in a locked or unlocked state. A password must be specified, either by the user or the calling application, to unlock the keyring.
 **/

/**
 * gnome_keyring_set_default_keyring:
 * @keyring: The keyring to make default
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Change the default keyring.
 *
 * For a synchronous version of this function see gnome_keyring_set_default_keyring_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_set_default_keyring (const gchar                             *keyring,
                                   GnomeKeyringOperationDoneCallback       callback,
                                   gpointer                                data,
                                   GDestroyNotify                          destroy_data)
{
#if 0
	GnomeKeyringOperation *op;

	op = operation_new (FALSE, callback, CALLBACK_DONE, data, destroy_data);
	if (!gkr_proto_encode_op_string (&op->send_buffer, GNOME_KEYRING_OP_SET_DEFAULT_KEYRING,
	                                 keyring)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = standard_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_set_default_keyring_sync:
 * @keyring: The keyring to make default
 *
 * Change the default keyring.
 *
 * For an asynchronous version of this function see gnome_keyring_set_default_keyring().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_set_default_keyring_sync (const char *keyring)
{
#if 0
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	if (!gkr_proto_encode_op_string (&send, GNOME_KEYRING_OP_SET_DEFAULT_KEYRING,
	                                 keyring)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_reply (&receive, &res)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

/**
 * gnome_keyring_get_default_keyring:
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Get the default keyring name, which will be passed to the @callback. If no
 * default keyring exists, then %NULL will be passed to the @callback. The
 * string will be freed after @callback returns.
 *
 * For a synchronous version of this function see gnome_keyring_get_default_keyring_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_get_default_keyring (GnomeKeyringOperationGetStringCallback  callback,
                                   gpointer                                data,
                                   GDestroyNotify                          destroy_data)
{
#if 0
	GnomeKeyringOperation *op;

	op = operation_new (FALSE, callback, CALLBACK_GET_STRING, data, destroy_data);
	if (!gkr_proto_encode_op_only (&op->send_buffer, GNOME_KEYRING_OP_GET_DEFAULT_KEYRING)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = string_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_get_default_keyring_sync:
 * @keyring: Location for the default keyring name to be returned.
 *
 * Get the default keyring name.
 *
 * The string returned in @keyring must be freed with g_free().
 *
 * For an asynchronous version of this function see gnome_keyring_get_default_keyring().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_get_default_keyring_sync (char **keyring)
{
#if 0
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	*keyring = NULL;

	if (!gkr_proto_encode_op_only (&send, GNOME_KEYRING_OP_GET_DEFAULT_KEYRING)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_string_reply (&receive, &res, keyring)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

static gboolean
list_keyring_names_foreach (DBusMessageIter *iter, gpointer user_data)
{
	GList **names = user_data;
	const char *path;
	gchar *name;

	if (dbus_message_iter_get_arg_type (iter) != DBUS_TYPE_OBJECT_PATH)
		return FALSE;

	/* The object path, gets converted into a name */
	dbus_message_iter_get_basic (iter, &path);
	name = decode_keyring_name (path);
	if (name != NULL)
		*names = g_list_prepend (*names, name);

	return TRUE;
}

static void
list_keyring_names_reply (Operation *op, DBusMessage *reply)
{
	GnomeKeyringOperationGetListCallback callback;
	GnomeKeyringResult res;
	GList *names = NULL;

	callback = op->user_callback;

	res = decode_property_variant_array (reply, list_keyring_names_foreach, &names);
	(*callback) (res, names, op->user_data);
	gnome_keyring_string_list_free (names);
}

/**
 * gnome_keyring_list_keyring_names:
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Get a list of keyring names.
 *
 * A %GList of null terminated strings will be passed to
 * the @callback. If no keyrings exist then an empty list will be passed to the
 * @callback. The list is freed after @callback returns.
 *
 * For a synchronous version of this function see gnome_keyring_list_keyrings_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_list_keyring_names  (GnomeKeyringOperationGetListCallback    callback,
                                   gpointer                                data,
                                   GDestroyNotify                          destroy_data)
{
	Operation *op;
	DBusMessage *req;

	req = prepare_property_get (SERVICE_PATH, SERVICE_INTERFACE, "Collections");
	g_return_val_if_fail (req, NULL);

	op = operation_new (callback, CALLBACK_GET_LIST, data, destroy_data);
	op->reply_handler = list_keyring_names_reply;
	start_operation (op, req);

	dbus_message_unref (req);
	operation_unref (op);
	return op;
}

/**
 * gnome_keyring_list_keyring_names_sync:
 * @keyrings: Location for a %GList of keyring names to be returned.
 *
 * Get a list of keyring names.
 *
 * The list returned in in @keyrings must be freed using
 * gnome_keyring_string_list_free().
 *
 * For an asynchronous version of this function see gnome_keyring_list_keyring_names().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_list_keyring_names_sync (GList **keyrings)
{
	DBusMessage *req, *reply;
	GnomeKeyringResult res;

	req = prepare_property_get (SERVICE_PATH, SERVICE_INTERFACE,
	                            "Collections");
	g_return_val_if_fail (req, BROKEN);

	res = send_to_service_and_simple_block (req, &reply);
	dbus_message_unref (req);

	if (res == GNOME_KEYRING_RESULT_OK)
		res = decode_property_variant_array (reply, list_keyring_names_foreach, keyrings);

	dbus_message_unref (reply);
	return res;
}

/**
 * gnome_keyring_lock_all:
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Lock all the keyrings, so that their contents may not be accessed without
 * first unlocking them with a password.
 *
 * For a synchronous version of this function see gnome_keyring_lock_all_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_lock_all (GnomeKeyringOperationDoneCallback       callback,
                        gpointer                                data,
                        GDestroyNotify                          destroy_data)
{
	DBusMessage *req;
	Operation *op;

	req = dbus_message_new_method_call (SECRETS_SERVICE, SERVICE_PATH,
	                                    SERVICE_INTERFACE, "LockService");
	g_return_val_if_fail (req, NULL);

	op = operation_new (callback, CALLBACK_DONE, data, destroy_data);
	op->reply_handler = standard_reply;
	start_operation (op, req);

	dbus_message_unref (req);
	operation_unref (op);
	return op;
}

/**
 * gnome_keyring_lock_all_sync:
 *
 * Lock all the keyrings, so that their contents may not eb accessed without
 * first unlocking them with a password.
 *
 * For an asynchronous version of this function see gnome_keyring_lock_all().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_lock_all_sync (void)
{
	DBusMessage *req, *reply;
	GnomeKeyringResult res;

	req = dbus_message_new_method_call (SECRETS_SERVICE, SERVICE_PATH,
	                                    SERVICE_INTERFACE, "LockService");
	g_return_val_if_fail (req, BROKEN);

	res = send_to_service_and_simple_block (req, &reply);
	dbus_message_unref (req);
	dbus_message_unref (reply);

	return res;
}

static void
create_keyring_reply (Operation *op, DBusMessage *reply)
{
	GnomeKeyringOperationDoneCallback callback;
	const char *collection;
	const char *prompt;

	g_assert (op->user_callback_type == CALLBACK_DONE);
	callback = op->user_callback;
	g_assert (callback);

	/* Parse the response */
	if (!dbus_message_get_args (reply, NULL, DBUS_TYPE_OBJECT_PATH, &collection,
	                            DBUS_TYPE_OBJECT_PATH, &prompt, DBUS_TYPE_INVALID)) {
		g_warning ("bad response to CreateCollection from service");
		(callback) (GNOME_KEYRING_RESULT_IO_ERROR, op->user_data);
		return;
	}

	/* No prompt, we're done */
	g_return_if_fail (prompt);
	if (g_str_equal (prompt, "/")) {
		(callback) (GNOME_KEYRING_RESULT_OK, op->user_data);

	/* A prompt, display it */
	} else {
		op->reply_handler = standard_reply;
		prompt_operation (op, prompt);
	}
}

static DBusMessage*
create_keyring_prepare (const gchar *keyring_name)
{
	DBusMessageIter iter, array, dict, variant;
	const gchar *label = "Label";
	DBusMessage *req;

	req = dbus_message_new_method_call (SECRETS_SERVICE, SERVICE_PATH,
	                                    SERVICE_INTERFACE, "CreateCollection");
	g_return_val_if_fail (req, NULL);

	dbus_message_iter_init_append (req, &iter);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, "{sv}", &array);
	dbus_message_iter_open_container (&array, DBUS_TYPE_DICT_ENTRY, NULL, &dict);
	dbus_message_iter_append_basic (&dict, DBUS_TYPE_STRING, &label);
	dbus_message_iter_open_container (&dict, DBUS_TYPE_VARIANT, "s", &variant);
	dbus_message_iter_append_basic (&variant, DBUS_TYPE_STRING, &keyring_name);
	dbus_message_iter_close_container (&dict, &variant);
	dbus_message_iter_close_container (&array, &dict);
	dbus_message_iter_close_container (&iter, &array);

	return req;
}

/**
 * gnome_keyring_create:
 * @keyring_name: The new keyring name. Must not be %NULL.
 * @password: The password for the new keyring. If %NULL user will be prompted.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Create a new keyring with the specified name. In most cases %NULL will be
 * passed as the @password, which will prompt the user to enter a password
 * of their choice.
 *
 * For a synchronous version of this function see gnome_keyring_create_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_create (const char                                  *keyring_name,
                      const char                                  *password,
                      GnomeKeyringOperationDoneCallback            callback,
                      gpointer                                     data,
                      GDestroyNotify                               destroy_data)
{
	DBusMessage *req;
	Operation *op;

	/* TODO: Password is currently ignored */

	op = operation_new (callback, CALLBACK_DONE, data, destroy_data);
	req = create_keyring_prepare (keyring_name);
	op->reply_handler = create_keyring_reply;
	start_operation (op, req);

	dbus_message_unref (req);
	return op;
}

/**
 * gnome_keyring_create_sync:
 * @keyring_name: The new keyring name. Must not be %NULL
 * @password: The password for the new keyring. If %NULL user will be prompted.
 *
 * Create a new keyring with the specified name. In most cases %NULL will be
 * passed in as the @password, which will prompt the user to enter a password
 * of their choice.
 *
 * For an asynchronous version of this function see gnome_keyring_create().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_create_sync (const char *keyring_name,
                           const char *password)
{
	DBusMessage *req, *reply;
	GnomeKeyringResult res;
	const char *collection;
	const char *prompt;

	req = create_keyring_prepare (keyring_name);
	g_return_val_if_fail (req, BROKEN);

	res = send_to_service_and_simple_block (req, &reply);
	dbus_message_unref (req);

	if (res != GNOME_KEYRING_RESULT_OK)
		return res;

	/* Parse the response */
	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_OBJECT_PATH, &collection,
	                           DBUS_TYPE_OBJECT_PATH, &prompt, DBUS_TYPE_INVALID)) {
		g_return_val_if_fail (prompt, BROKEN);
		if (!g_str_equal (prompt, "/")) {
			dbus_message_unref (reply);
			res = prompt_service_and_block (prompt, &reply);
		}
	} else {
		g_warning ("bad response to CreateCollection from service");
		res = GNOME_KEYRING_RESULT_IO_ERROR;
	}

	dbus_message_unref (reply);

	return res;
}

/**
 * gnome_keyring_unlock:
 * @keyring: The name of the keyring to unlock, or %NULL for the default keyring.
 * @password: The password to unlock the keyring with, or %NULL to prompt the user.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Unlock a @keyring, so that its contents may be accessed. In most cases %NULL
 * will be passed as the @password, which will prompt the user to enter the
 * correct password.
 *
 * Most keyring operations involving items require that you first unlock the
 * keyring. One exception is gnome_keyring_find_items() and related functions.
 *
 * For a synchronous version of this function see gnome_keyring_unlock_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_unlock (const char                                  *keyring,
                      const char                                  *password,
                      GnomeKeyringOperationDoneCallback            callback,
                      gpointer                                     data,
                      GDestroyNotify                               destroy_data)
{
#if 0
	GnomeKeyringOperation *op;

	op = operation_new (FALSE, callback, CALLBACK_DONE, data, destroy_data);

	/* Automatically secures buffer */
	if (!gkr_proto_encode_op_string_secret (&op->send_buffer, GNOME_KEYRING_OP_UNLOCK_KEYRING,
	                                        keyring, password)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = standard_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_unlock_sync:
 * @keyring_name: The name of the keyring to unlock, or %NULL for the default keyring.
 * @password: The password to unlock the keyring with, or %NULL to prompt the user.
 *
 * Unlock a @keyring, so that its contents may be accessed. In most cases %NULL
 * will be passed in as the @password, which will prompt the user to enter the
 * correct password.
 *
 * Most keyring opretaions involving items require that yo ufirst unlock the
 * keyring. One exception is gnome_keyring_find_items_sync() and related functions.
 *
 * For an asynchronous version of this function see gnome_keyring_unlock().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_unlock_sync (const char *keyring,
                           const char *password)
{
#if 0
	EggBuffer send, receive;
	GnomeKeyringResult res;

	/* Use secure non-pageable buffer */
	egg_buffer_init_full (&send, 128, SECURE_ALLOCATOR);

	if (!gkr_proto_encode_op_string_secret (&send, GNOME_KEYRING_OP_UNLOCK_KEYRING,
	                                        keyring, password)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_reply (&receive, &res)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

/**
 * gnome_keyring_lock:
 * @keyring: The name of the keyring to lock, or %NULL for the default keyring.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Lock a @keyring, so that its contents may not be accessed without first
 * supplying a password.
 *
 * Most keyring operations involving items require that you first unlock the
 * keyring. One exception is gnome_keyring_find_items() and related functions.
 *
 * For a synchronous version of this function see gnome_keyring_lock_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_lock (const char                                  *keyring,
                    GnomeKeyringOperationDoneCallback            callback,
                    gpointer                                     data,
                    GDestroyNotify                               destroy_data)
{
#if 0
	GnomeKeyringOperation *op;

	op = operation_new (FALSE, callback, CALLBACK_DONE, data, destroy_data);

	if (!gkr_proto_encode_op_string (&op->send_buffer, GNOME_KEYRING_OP_LOCK_KEYRING,
	                                 keyring)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = standard_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_unlock_sync:
 * @keyring: The name of the keyring to lock, or %NULL for the default keyring.
 *
 * Lock a @keyring, so that its contents may not be accessed without first
 * supplying a password.
 *
 * Most keyring opretaions involving items require that you first unlock the
 * keyring. One exception is gnome_keyring_find_items_sync() and related functions.
 *
 * For an asynchronous version of this function see gnome_keyring_lock().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_lock_sync (const char *keyring)
{
#if 0
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	if (!gkr_proto_encode_op_string (&send, GNOME_KEYRING_OP_LOCK_KEYRING,
	                                 keyring)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_reply (&receive, &res)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

/**
 * gnome_keyring_delete:
 * @keyring: The name of the keyring to delete. Cannot be %NULL.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Delete @keyring. Once a keyring is deleted there is no mechanism for
 * recovery of its contents.
 *
 * For a synchronous version of this function see gnome_keyring_delete_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_delete (const char                                  *keyring,
                      GnomeKeyringOperationDoneCallback            callback,
                      gpointer                                     data,
                      GDestroyNotify                               destroy_data)
{
#if 0
	GnomeKeyringOperation *op;

	op = operation_new (FALSE, callback, CALLBACK_DONE, data, destroy_data);

	if (!gkr_proto_encode_op_string (&op->send_buffer, GNOME_KEYRING_OP_DELETE_KEYRING,
	                                 keyring)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = standard_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_delete_sync:
 * @keyring: The name of the keyring to delete. Cannot be %NULL
 *
 * Delete @keyring. Once a keyring is deleted there is no mechanism for
 * recovery of its contents.
 *
 * For an asynchronous version of this function see gnome_keyring_delete().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_delete_sync (const char *keyring)
{
#if 0
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	if (!gkr_proto_encode_op_string (&send, GNOME_KEYRING_OP_DELETE_KEYRING,
	                                 keyring)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_reply (&receive, &res)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

/**
 * gnome_keyring_change_password:
 * @keyring: The name of the keyring to change the password for. Cannot be %NULL.
 * @original: The old keyring password, or %NULL to prompt the user for it.
 * @password: The new keyring password, or %NULL to prompt the user for it.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Change the password for a @keyring. In most cases you would specify %NULL for
 * both the @original and @password arguments and allow the user to type the
 * correct passwords.
 *
 * For a synchronous version of this function see gnome_keyring_change_password_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_change_password (const char                                  *keyring,
                               const char                                  *original,
                               const char                                  *password,
                               GnomeKeyringOperationDoneCallback            callback,
                               gpointer                                     data,
                               GDestroyNotify                               destroy_data)
{
#if 0
	GnomeKeyringOperation *op;

	op = operation_new (FALSE, callback, CALLBACK_DONE, data, destroy_data);

	/* Automatically secures buffer */
	if (!gkr_proto_encode_op_string_secret_secret (&op->send_buffer,
	                                               GNOME_KEYRING_OP_CHANGE_KEYRING_PASSWORD,
	                                               keyring, original, password)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = standard_reply;
	start_and_take_operation (op);

	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}


/**
 * gnome_keyring_change_password_sync:
 * @keyring: The name of the keyring to change the password for. Cannot be %NULL
 * @original: The old keyring password, or %NULL to prompt the user for it.
 * @password: The new keyring password, or %NULL to prompt the user for it.
 *
 * Change the password for @keyring. In most cases you would specify %NULL for
 * both the @original and @password arguments and allow the user to type the
 * correct passwords.
 *
 * For an asynchronous version of this function see gnome_keyring_change_password().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_change_password_sync (const char *keyring_name,
                                    const char *original, const char *password)
{
#if 0
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, SECURE_ALLOCATOR);

	if (!gkr_proto_encode_op_string_secret_secret (&send,
	                                               GNOME_KEYRING_OP_CHANGE_KEYRING_PASSWORD,
	                                               keyring_name, original, password)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_reply (&receive, &res)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

static gboolean
get_keyring_info_foreach (const gchar *property, DBusMessageIter *iter, gpointer user_data)
{
	GnomeKeyringInfo *info = user_data;
	dbus_bool_t bval;
	dbus_int64_t i64val;

	if (strcmp (property, "Locked")) {
		if (!dbus_message_iter_get_arg_type (iter) != DBUS_TYPE_BOOLEAN)
			return FALSE;
		dbus_message_iter_get_basic (iter, &bval);
		info->is_locked = (bval == TRUE);

	} else if (strcmp (property, "Created")) {
		if (!dbus_message_iter_get_arg_type (iter) != DBUS_TYPE_INT64)
			return FALSE;
		dbus_message_iter_get_basic (iter, &i64val);
		info->ctime = (time_t)i64val;

	} else if (strcmp (property, "Modified")) {
		if (!dbus_message_iter_get_arg_type (iter) != DBUS_TYPE_INT64)
			return FALSE;
		dbus_message_iter_get_basic (iter, &i64val);
		info->ctime = (time_t)i64val;
	}

	return TRUE;
}

static void
get_keyring_info_reply (Operation *op, DBusMessage *reply)
{
	GnomeKeyringOperationGetKeyringInfoCallback callback;
	GnomeKeyringResult res;
	GnomeKeyringInfo *info;

	g_assert (op->user_callback_type == CALLBACK_GET_KEYRING_INFO);
	callback = op->user_callback;

	info = g_new0 (GnomeKeyringInfo, 1);
	res = decode_property_dict (reply, get_keyring_info_foreach, info);
	(*callback) (res, res == GNOME_KEYRING_RESULT_OK ? info : NULL, op->user_data);
	gnome_keyring_info_free (info);
}

/**
 * gnome_keyring_get_info:
 * @keyring: The name of the keyring, or %NULL for the default keyring.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Get information about the @keyring. The resulting #GnomeKeyringInfo structure
 * will be passed to @callback. The structure is freed after @callback returns.
 *
 * For a synchronous version of this function see gnome_keyring_get_info_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_get_info (const char                                  *keyring,
                        GnomeKeyringOperationGetKeyringInfoCallback  callback,
                        gpointer                                     data,
                        GDestroyNotify                               destroy_data)
{
	DBusMessage *req;
	Operation *op;
	gchar *path;

	path = encode_keyring_name (keyring);
	g_return_val_if_fail (path, NULL);

	req = prepare_property_getall (path, COLLECTION_INTERFACE);

	op = operation_new (callback, CALLBACK_GET_KEYRING_INFO, data, destroy_data);
	op->reply_handler = get_keyring_info_reply;
	start_operation (op, req);

	dbus_message_unref (req);
	operation_unref (op);
	g_free (path);
	return op;
}

/**
 * gnome_keyring_get_info_sync:
 * @keyring: The name of the keyring, or %NULL for the default keyring.
 * @info: Location for the information about the keyring to be returned.
 *
 * Get information about @keyring.
 *
 * The #GnomeKeyringInfo structure returned in @info must be freed with
 * gnome_keyring_info_free().
 *
 * For an asynchronous version of this function see gnome_keyring_get_info().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_get_info_sync (const char        *keyring,
                             GnomeKeyringInfo **info)
{
	DBusMessage *req, *reply;
	GnomeKeyringResult res;
	GnomeKeyringInfo *inf;
	gchar *path;

	g_return_val_if_fail (info, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);

	path = encode_keyring_name (keyring);
	g_return_val_if_fail (path, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	req = prepare_property_getall (path, COLLECTION_INTERFACE);
	g_return_val_if_fail (req, BROKEN);
	g_free (path);

	res = send_to_service_and_simple_block (req, &reply);
	dbus_message_unref (req);

	if (res == GNOME_KEYRING_RESULT_OK) {
		inf = g_new (GnomeKeyringInfo, 1);
		res = decode_property_dict (reply, get_keyring_info_foreach, info);
		if (res != GNOME_KEYRING_RESULT_OK)
			*info = inf;
		else
			gnome_keyring_info_free (inf);
	}

	dbus_message_unref (reply);
	return res;
}

/**
 * gnome_keyring_set_info:
 * @keyring: The name of the keyring, or %NULL for the default keyring.
 * @info: A structure containing flags and info for the keyring.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Set flags and info for the @keyring. The only fields in @info that are used
 * are %lock_on_idle and %lock_timeout.
 *
 * For a synchronous version of this function see gnome_keyring_set_info_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_set_info (const char                                  *keyring,
                        GnomeKeyringInfo                            *info,
                        GnomeKeyringOperationDoneCallback            callback,
                        gpointer                                     data,
                        GDestroyNotify                               destroy_data)
{
	Operation *op;
	gchar *path;

	g_return_val_if_fail (info, NULL);

	path = encode_keyring_name (keyring);
	g_return_val_if_fail (path, NULL);

	/*
	 * TODO: Currently nothing to do. lock_on_idle and lock_timeout are not
	 * implemented in the DBus API. They were never used by the old
	 * gnome-keyring-daemon either.
	 */

	op = operation_new (callback, CALLBACK_DONE, data, destroy_data);
	operation_schedule_completed (op, GNOME_KEYRING_RESULT_OK);

	g_free (path);
	return op;
}

/**
 * gnome_keyring_set_info_sync:
 * @keyring: The name of the keyring, or %NULL for the default keyring.
 * @info: A structure containing flags and info for the keyring.
 *
 * Set flags and info for @keyring. The only fields in @info that are used
 * are %lock_on_idle and %lock_timeout.
 *
 * For an asynchronous version of this function see gnome_keyring_set_info().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_set_info_sync (const char       *keyring,
                             GnomeKeyringInfo *info)
{
	gchar *path;

	g_return_val_if_fail (info, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);

	path = encode_keyring_name (keyring);
	g_return_val_if_fail (path, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);

	/*
	 * TODO: Currently nothing to do. lock_on_idle and lock_timeout are not
	 * implemented in the DBus API. They were never used by the old
	 * gnome-keyring-daemon either.
	 */

	g_free (path);
	return GNOME_KEYRING_RESULT_OK;
}

static gboolean
list_item_ids_foreach (DBusMessageIter *iter, gpointer data)
{
	GList **ids = data;
	const char *path;
	guint32 id;

	if (dbus_message_iter_get_arg_type (iter) != DBUS_TYPE_OBJECT_PATH)
		return FALSE;

	/* The object path, gets converted into a name */
	dbus_message_iter_get_basic (iter, &path);
	if (decode_item_id (path, &id))
		*ids = g_list_prepend (*ids, GUINT_TO_POINTER (id));
	else
		g_message ("unsupported item. identifier is not an integer: %s", path);

	return TRUE;
}

static void
list_item_ids_reply (Operation *op, DBusMessage *reply)
{
	GnomeKeyringOperationGetListCallback callback;
	GnomeKeyringResult res;
	GList *ids = NULL;

	g_assert (op->user_callback_type == CALLBACK_GET_LIST);
	callback = op->user_callback;

	res = decode_property_variant_array (reply, list_item_ids_foreach, &ids);
	(*callback) (res, ids, op->user_data);
	g_list_free (ids);
}

/**
 * gnome_keyring_list_item_ids:
 * @keyring: The name of the keyring, or %NULL for the default keyring.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Get a list of all the ids for items in @keyring. These are passed in a %GList
 * to the @callback. Use GPOINTER_TO_UINT() on the list to access the integer ids.
 * The list is freed after @callback returns.
 *
 * All items that are not flagged as %GNOME_KEYRING_ITEM_APPLICATION_SECRET are
 * included in the list. This includes items that the calling application may not
 * (yet) have access to.
 *
 * For a synchronous version of this function see gnome_keyring_list_item_ids_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_list_item_ids (const char                                  *keyring,
                             GnomeKeyringOperationGetListCallback         callback,
                             gpointer                                     data,
                             GDestroyNotify                               destroy_data)
{
	DBusMessage *req;
	Operation *op;
	gchar *path;

	path = encode_keyring_name (keyring);
	g_return_val_if_fail (path, NULL);

	req = prepare_property_get (path, COLLECTION_INTERFACE, "Items");

	op = operation_new (callback, CALLBACK_GET_LIST, data, destroy_data);
	op->reply_handler = list_item_ids_reply;
	start_operation (op, req);

	dbus_message_unref (req);
	operation_unref (op);
	g_free (path);
	return op;
}

/**
 * gnome_keyring_list_item_ids_sync:
 * @keyring: The name of the keyring, or %NULL for the default keyring.
 * @ids: The location to store a %GList of item ids (ie: unsigned integers).
 *
 * Get a list of all the ids for items in @keyring.
 *
 * Use GPOINTER_TO_UINT() on the list to access the integer ids. The list
 * should be freed with g_list_free().
 *
 * For an asynchronous version of this function see gnome_keyring_list_item_ids().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_list_item_ids_sync (const char  *keyring,
                                  GList      **ids)
{
	DBusMessage *req, *reply;
	GnomeKeyringResult res;
	gchar *path;

	g_return_val_if_fail (ids, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);

	path = encode_keyring_name (keyring);
	g_return_val_if_fail (path, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);

	req = prepare_property_get (path, COLLECTION_INTERFACE, "Items");
	g_return_val_if_fail (req, BROKEN);
	g_free (path);

	res = send_to_service_and_simple_block (req, &reply);
	dbus_message_unref (req);

	if (res == GNOME_KEYRING_RESULT_OK)
		res = decode_property_variant_array (reply, list_item_ids_foreach, ids);

	dbus_message_unref (reply);
	return res;
}

/**
 * SECTION:gnome-keyring-daemon
 * @title: Daemon Management Functions
 * @short_description: Functions used by session to run the Gnome Keyring Daemon.
 *
 * These functions are not used by most applications using Gnome Keyring.
 **/

/**
 * gnome_keyring_daemon_set_display_sync:
 * @display: Deprecated
 *
 * Deprecated. No longer supported, always fails.
 **/
GnomeKeyringResult
gnome_keyring_daemon_set_display_sync (const char *display)
{
	g_return_val_if_fail (display, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	return GNOME_KEYRING_RESULT_DENIED;
}

/**
 * gnome_keyring_daemon_prepare_environment_sync:
 *
 * Deprecated. No longer supported, call is ignored.
 **/
GnomeKeyringResult
gnome_keyring_daemon_prepare_environment_sync (void)
{
	return GNOME_KEYRING_RESULT_OK;
}


#if 0
static gboolean
find_items_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetListCallback callback;
	GList *found_items;

	callback = op->user_callback;

	if (!gkr_proto_decode_find_reply (&op->receive_buffer, &result, &found_items)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, found_items, op->user_data);
		gnome_keyring_found_list_free (found_items);
	}

	/* Operation is done */
	return TRUE;
}
#endif

/**
 * SECTION:gnome-keyring-find
 * @title: Search Functionality
 * @short_description: Find Keyring Items
 *
 * A find operation searches through all keyrings for items that match the
 * attributes. The user may have been prompted to unlock necessary keyrings, and
 * user will have been prompted for access to the items if needed.
 *
 * A find operation may return multiple or zero results.
 **/

/**
 * gnome_keyring_find_items:
 * @type: The type of items to find.
 * @attributes: A list of attributes to search for. This cannot be an empty list.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Searches through all keyrings for items that match the @attributes. The matches
 * are for exact equality.
 *
 * A %GList of GnomeKeyringFound structures are passed to the @callback. The
 * list and structures are freed after the callback returns.
 *
 * The user may have been prompted to unlock necessary keyrings, and user will
 * have been prompted for access to the items if needed.
 *
 * For a synchronous version of this function see gnome_keyring_find_items_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_find_items  (GnomeKeyringItemType                  type,
                           GnomeKeyringAttributeList            *attributes,
                           GnomeKeyringOperationGetListCallback  callback,
                           gpointer                              data,
                           GDestroyNotify                        destroy_data)
{
#if 0
	GnomeKeyringOperation *op;

	/* Use a secure receive buffer */
	op = operation_new (TRUE, callback, CALLBACK_GET_LIST, data, destroy_data);

	if (!gkr_proto_encode_find (&op->send_buffer, type, attributes)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = find_items_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

#if 0
static GnomeKeyringAttributeList *
make_attribute_list_va (va_list args)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttribute attribute;
	char *str;
	guint32 val;

	attributes = g_array_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute));

	while ((attribute.name = va_arg (args, char *)) != NULL) {
		attribute.type = va_arg (args, GnomeKeyringAttributeType);

		switch (attribute.type) {
		case GNOME_KEYRING_ATTRIBUTE_TYPE_STRING:
			str = va_arg (args, char *);
			attribute.value.string = str;
			g_array_append_val (attributes, attribute);
			break;
		case GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32:
			val = va_arg (args, guint32);
			attribute.value.integer = val;
			g_array_append_val (attributes, attribute);
			break;
		default:
			g_array_free (attributes, TRUE);
			return NULL;
		}
	}
	return attributes;
}
#endif

/**
 * gnome_keyring_find_itemsv:
 * @type: The type of items to find.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Searches through all keyrings for items that match the specified attributes.
 * The matches are for exact equality.
 *
 * The variable argument list should contain a) The attribute name as a null
 * terminated string, followed by b) The attribute type, either
 * %GNOME_KEYRING_ATTRIBUTE_TYPE_STRING or %GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32
 * and then the c) attribute value, either a character string, or 32-bit
 * unsigned int. The list should be terminated with a NULL.
 *
 * A %GList of GnomeKeyringFound structures are passed to the @callback. The
 * list and structures are freed after the callback returns.
 *
 * The user may have been prompted to unlock necessary keyrings, and user will
 * have been prompted for access to the items if needed.
 *
 * For a synchronous version of this function see gnome_keyring_find_itemsv_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_find_itemsv (GnomeKeyringItemType                  type,
                           GnomeKeyringOperationGetListCallback  callback,
                           gpointer                              data,
                           GDestroyNotify                        destroy_data,
                           ...)
{
#if 0
	GnomeKeyringOperation *op;
	GnomeKeyringAttributeList *attributes;
	va_list args;

	/* Use a secure receive buffer */
	op = operation_new (TRUE, callback, CALLBACK_GET_LIST, data, destroy_data);

	va_start (args, destroy_data);
	attributes = make_attribute_list_va (args);
	va_end (args);
	if (attributes == NULL) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		return op;
	}

	if (!gkr_proto_encode_find (&op->send_buffer, type, attributes))  {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	g_array_free (attributes, TRUE);

	op->reply_handler = find_items_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_find_items_sync:
 * @type: The type of items to find.
 * @attributes: A list of attributes to search for. This cannot be an empty list.
 * @found: The location to return a list of #GnomeKeyringFound pointers.
 *
 * Searches through all keyrings for items that match the @attributes and @type.
 * The matches are for exact equality.
 *
 * A %GList of GnomeKeyringFound structures is returned in @found. The list may
 * have zero items if nothing matched the criteria. The list should be freed
 * using gnome_keyring_found_list_free().
 *
 * The user may have been prompted to unlock necessary keyrings, and user will
 * have been prompted for access to the items if needed.
 *
 * For an asynchronous version of this function see gnome_keyring_find_items().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_find_items_sync (GnomeKeyringItemType        type,
                               GnomeKeyringAttributeList  *attributes,
                               GList                     **found)
{
#if 0
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	*found = NULL;

	if (!gkr_proto_encode_find (&send, type, attributes)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	/* Use a secure receive buffer */
	egg_buffer_init_full (&receive, 128, SECURE_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_find_reply (&receive, &res, found)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

/**
 * gnome_keyring_find_itemsv_sync:
 * @type: The type of items to find.
 * @found: The location to return a list of #GnomeKeyringFound pointers.
 *
 * Searches through all keyrings for items that match the @attributes and @type.
 * The matches are for exact equality.
 *
 * The variable argument list should contain a) The attribute name as a null
 * terminated string, followed by b) The attribute type, either
 * %GNOME_KEYRING_ATTRIBUTE_TYPE_STRING or %GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32
 * and then the c) attribute value, either a character string, or 32-bit
 * unsigned int. The list should be terminated with a NULL.
 *
 * A %GList of GnomeKeyringFound structures is returned in @found. The list may
 * have zero items if nothing matched the criteria. The list should be freed
 * using gnome_keyring_found_list_free().
 *
 * The user may have been prompted to unlock necessary keyrings, and user will
 * have been prompted for access to the items if needed.
 *
 * For an asynchronous version of this function see gnome_keyring_find_items().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_find_itemsv_sync  (GnomeKeyringItemType        type,
                                 GList                     **found,
                                 ...)
{
#if 0
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringResult res;
	va_list args;

	va_start (args, found);
	attributes = make_attribute_list_va (args);
	va_end (args);
	if (attributes == NULL) {
		return  GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	res = gnome_keyring_find_items_sync (type, attributes, found);
	g_array_free (attributes, TRUE);
	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

/**
 * SECTION:gnome-keyring-items
 * @title: Keyring Items
 * @short_description: Keyring items each hold a secret and a number of attributes.
 *
 * A keyring contains multiple items. Each item has a secret, attributes and access
 * information associated with it.
 *
 * An item is identified by an unsigned integer unique to the keyring in which it
 * exists. An item's name is for displaying to the user. Each item has a single secret,
 * which is a null-terminated string. This secret is stored in non-pageable memory, and
 * encrypted on disk. All of this information is exposed via #GnomeKeyringItemInfo
 * pointers.
 *
 * Attributes allow various other pieces of information to be associated with an item.
 * These can also be used to search for relevant items. Attributes are accessed with
 * #GnomeKeyringAttribute structures and built into lists using #GnomeKeyringAttributeList.
 *
 * Each item has an access control list, which specifies the applications that
 * can read, write or delete an item. The read access applies only to reading the secret.
 * All applications can read other parts of the item. ACLs are accessed and changed
 * through #GnomeKeyringAccessControl pointers.
 **/

/**
 * gnome_keyring_item_create:
 * @keyring: The name of the keyring in which to create the item, or NULL for the default keyring.
 * @type: The item type.
 * @display_name: The name of the item. This will be displayed to the user where necessary.
 * @attributes: A (possibly empty) list of attributes to store with the item.
 * @secret: The password or secret of the item.
 * @update_if_exists: If true, then another item matching the type, and attributes
 *  will be updated instead of creating a new item.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Create a new item in a keyring.
 *
 * The @secret must be a null terminated string. It should be allocated using secure
 * memory whenever possible. See gnome_keyring_memory_strdup()
 *
 * The user may have been prompted to unlock necessary keyrings. If %NULL is
 * specified as the @keyring and no default keyring exists, the user will be
 * prompted to create a new keyring.
 *
 * When @update_if_exists is set to %TRUE, the user may be prompted for access
 * to the previously existing item.
 *
 * Whether a new item is created or not, id of the item will be passed to
 * the @callback.
 *
 * For a synchronous version of this function see gnome_keyring_item_create_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_create (const char                          *keyring,
                           GnomeKeyringItemType                 type,
                           const char                          *display_name,
                           GnomeKeyringAttributeList           *attributes,
                           const char                          *secret,
                           gboolean                             update_if_exists,
                           GnomeKeyringOperationGetIntCallback  callback,
                           gpointer                             data,
                           GDestroyNotify                       destroy_data)
{
#if 0
	GnomeKeyringOperation *op;

	op = operation_new (FALSE, callback, CALLBACK_GET_INT, data, destroy_data);

	/* Automatically secures buffer */
	if (!gkr_proto_encode_create_item (&op->send_buffer, keyring, display_name,
	                                   attributes, secret, type, update_if_exists)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = int_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_item_create_sync():
 * @keyring: The name of the keyring in which to create the item, or NULL for the default keyring.
 * @type: The item type.
 * @display_name: The name of the item. This will be displayed to the user where necessary.
 * @attributes: A (possibly empty) list of attributes to store with the item.
 * @secret: The password or secret of the item.
 * @update_if_exists: If true, then another item matching the type, and attributes
 *  will be updated instead of creating a new item.
 * @item_id: return location for the id of the created/updated keyring item.
 *
 * Create a new item in a keyring.
 *
 * The @secret must be a null terminated string. It should be allocated using secure
 * memory whenever possible. See gnome_keyring_memory_strdup()
 *
 * The user may have been prompted to unlock necessary keyrings. If %NULL is
 * specified as the @keyring and no default keyring exists, the user will be
 * prompted to create a new keyring.
 *
 * When @update_if_exists is set to %TRUE, the user may be prompted for access
 * to the previously existing item.
 *
 * For an asynchronous version of this function see gnome_keyring_create().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_item_create_sync (const char                                 *keyring,
                                GnomeKeyringItemType                        type,
                                const char                                 *display_name,
                                GnomeKeyringAttributeList                  *attributes,
                                const char                                 *secret,
                                gboolean                                    update_if_exists,
                                guint32                                    *item_id)
{
#if 0
	EggBuffer send, receive;
	GnomeKeyringResult res;

	/* Use a secure buffer */
	egg_buffer_init_full (&send, 128, SECURE_ALLOCATOR);

	*item_id = 0;

	if (!gkr_proto_encode_create_item (&send, keyring, display_name, attributes,
	                                   secret, type, update_if_exists)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_integer_reply (&receive, &res, item_id)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

/**
 * gnome_keyring_item_delete:
 * @keyring: The name of the keyring from which to delete the item, or NULL for the default keyring.
 * @id: The id of the item
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Delete an item in a keyring.
 *
 * The user may be prompted if the calling application doesn't have necessary
 * access to delete the item.
 *
 * For an asynchronous version of this function see gnome_keyring_delete().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_delete (const char                                 *keyring,
                           guint32                                     id,
                           GnomeKeyringOperationDoneCallback           callback,
                           gpointer                                    data,
                           GDestroyNotify                              destroy_data)
{
#if 0
	GnomeKeyringOperation *op;

	op = operation_new (FALSE, callback, CALLBACK_DONE, data, destroy_data);

	if (!gkr_proto_encode_op_string_int (&op->send_buffer, GNOME_KEYRING_OP_DELETE_ITEM,
	                                     keyring, id)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = standard_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_item_delete_sync:
 * @keyring: The name of the keyring from which to delete the item, or NULL for the default keyring.
 * @id: The id of the item
 *
 * Delete an item in a keyring.
 *
 * The user may be prompted if the calling application doesn't have necessary
 * access to delete the item.
 *
 * For an asynchronous version of this function see gnome_keyring_item_delete().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_item_delete_sync (const char *keyring,
                                guint32     id)
{
#if 0
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	if (!gkr_proto_encode_op_string_int (&send, GNOME_KEYRING_OP_DELETE_ITEM,
	                                     keyring, id)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	egg_buffer_uninit (&receive);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

#if 0
static gboolean
get_item_info_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetItemInfoCallback callback;
	GnomeKeyringItemInfo *info;

	callback = op->user_callback;

	if (!gkr_proto_decode_get_item_info_reply (&op->receive_buffer, &result, &info)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, info, op->user_data);
		gnome_keyring_item_info_free (info);
	}

	/* Operation is done */
	return TRUE;
}
#endif

/**
 * gnome_keyring_item_get_info:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Get information about an item and its secret.
 *
 * The user may be prompted if the calling application doesn't have necessary
 * access to read the item with its secret.
 *
 * A #GnomeKeyringItemInfo structure will be passed to the @callback. This structure
 * will be freed after @callback returns.
 *
 * For a synchronous version of this function see gnome_keyring_item_get_info_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_get_info (const char                                 *keyring,
                             guint32                                     id,
                             GnomeKeyringOperationGetItemInfoCallback    callback,
                             gpointer                                    data,
                             GDestroyNotify                              destroy_data)
{
#if 0
	GnomeKeyringOperation *op;

	/* Use a secure receive buffer */
	op = operation_new (TRUE, callback, CALLBACK_GET_ITEM_INFO, data, destroy_data);

	if (!gkr_proto_encode_op_string_int (&op->send_buffer, GNOME_KEYRING_OP_GET_ITEM_INFO,
	                                     keyring, id)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = get_item_info_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_item_get_info_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @info: The location to return a #GnomeKeyringItemInfo pointer.
 *
 * Get information about an item and its secret.
 *
 * The user may be prompted if the calling application doesn't have necessary
 * access to read the item with its secret.
 *
 * A #GnomeKeyringItemInfo structure will be returned in @info. This must be
 * freed using gnome_keyring_item_info_free().
 *
 * For an asynchronous version of this function see gnome_keyring_item_get_info().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_item_get_info_sync (const char            *keyring,
                                  guint32                id,
                                  GnomeKeyringItemInfo **info)
{
#if 0
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	*info = NULL;

	if (!gkr_proto_encode_op_string_int (&send, GNOME_KEYRING_OP_GET_ITEM_INFO,
	                                     keyring, id)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	/* Use a secure buffer */
	egg_buffer_init_full (&receive, 128, SECURE_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_get_item_info_reply (&receive, &res, info)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

/**
 * gnome_keyring_item_get_info_full:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @flags: The parts of the item to retrieve.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Get information about an item, optionally retrieving its secret.
 *
 * If @flags includes %GNOME_KEYRING_ITEM_INFO_SECRET then the user may be
 * prompted if the calling application doesn't have necessary access to read
 * the item with its secret.
 *
 * A #GnomeKeyringItemInfo pointer will be passed to the @callback. Certain fields
 * of this structure may be NULL or zero if they were not specified in @flags. This
 * structure will be freed after @callback returns.
 *
 * For a synchronous version of this function see gnome_keyring_item_get_info_full_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_get_info_full (const char                                 *keyring,
                                  guint32                                     id,
                                  guint32                                     flags,
                                  GnomeKeyringOperationGetItemInfoCallback    callback,
                                  gpointer                                    data,
                                  GDestroyNotify                              destroy_data)
{
#if 0
	GnomeKeyringOperation *op;

	/* Use a secure receive buffer */
	op = operation_new (TRUE, callback, CALLBACK_GET_ITEM_INFO, data, destroy_data);

	if (!gkr_proto_encode_op_string_int_int (&op->send_buffer,
	                                         GNOME_KEYRING_OP_GET_ITEM_INFO_FULL,
	                                         keyring, id, flags)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = get_item_info_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_item_get_info_full_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @flags: The parts of the item to retrieve.
 * @info: The location to return a #GnomeKeyringItemInfo pointer.
 *
 * Get information about an item, optionally retrieving its secret.
 *
 * If @flags includes %GNOME_KEYRING_ITEM_INFO_SECRET then the user may be
 * prompted if the calling application doesn't have necessary access to read
 * the item with its secret.
 *
 * A #GnomeKeyringItemInfo structure will be returned in @info. Certain fields
 * of this structure may be NULL or zero if they were not specified in @flags.
 * This must be freed using gnome_keyring_item_info_free().
 *
 * For an asynchronous version of this function see gnome_keyring_item_get_info_full().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_item_get_info_full_sync (const char              *keyring,
                                       guint32                  id,
                                       guint32                  flags,
                                       GnomeKeyringItemInfo   **info)
{
#if 0
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	*info = NULL;

	if (!gkr_proto_encode_op_string_int_int (&send, GNOME_KEYRING_OP_GET_ITEM_INFO_FULL,
	                                         keyring, id, flags)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	/* Use a secure buffer */
	egg_buffer_init_full (&receive, 128, SECURE_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_get_item_info_reply (&receive, &res, info)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

/**
 * gnome_keyring_item_set_info:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @info: The item info to save into the item.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Set information on an item, like its display name, secret etc...
 *
 * Only the fields in the @info pointer that are non-null or non-zero will be
 * set on the item.
 *
 * For a synchronous version of this function see gnome_keyring_item_set_info_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_set_info (const char                                 *keyring,
                             guint32                                     id,
                             GnomeKeyringItemInfo                       *info,
                             GnomeKeyringOperationDoneCallback           callback,
                             gpointer                                    data,
                             GDestroyNotify                              destroy_data)
{
#if 0
	GnomeKeyringOperation *op;

	op = operation_new (FALSE, callback, CALLBACK_DONE, data, destroy_data);

	/* Automatically secures buffer */
	if (!gkr_proto_encode_set_item_info (&op->send_buffer, keyring, id, info)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = standard_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_item_set_info_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @info: The item info to save into the item.
 *
 * Set information on an item, like its display name, secret etc...
 *
 * Only the fields in the @info pointer that are non-null or non-zero will be
 * set on the item.
 *
 * For an asynchronous version of this function see gnome_keyring_item_set_info().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_item_set_info_sync (const char           *keyring,
                                  guint32               id,
                                  GnomeKeyringItemInfo *info)
{
#if 0
	EggBuffer send, receive;
	GnomeKeyringResult res;

	/* Use a secure memory buffer */
	egg_buffer_init_full (&send, 128, SECURE_ALLOCATOR);

	if (!gkr_proto_encode_set_item_info (&send, keyring, id, info)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	egg_buffer_uninit (&receive);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

static gboolean
get_attributes_foreach (DBusMessageIter *iter, gpointer user_data)
{
	GHashTable *table = user_data;
	DBusMessageIter dict;
	const char *name;
	const char *value;

	if (!dbus_message_iter_get_arg_type (iter) != DBUS_TYPE_DICT_ENTRY)
		return FALSE;

	dbus_message_iter_recurse (iter, &dict);
	if (!dbus_message_iter_get_arg_type (&dict) != DBUS_TYPE_STRING)
		return FALSE;
	dbus_message_iter_get_basic (&dict, &name);

	dbus_message_iter_next (&dict);
	if (!dbus_message_iter_get_arg_type (&dict) != DBUS_TYPE_STRING)
		return FALSE;
	dbus_message_iter_get_basic (&dict, &value);

	/* These strings will last as long as the message, so no need to dup */
	g_return_val_if_fail (name && value, FALSE);
	g_hash_table_insert (table, (char*)name, (char*)value);
	return TRUE;
}

static GnomeKeyringResult
get_attributes_decode (DBusMessage *reply, GnomeKeyringAttributeList *attrs)
{
	GnomeKeyringResult res;
	GHashTableIter iter;
	GHashTable *table;
	const char *name;
	const char *value;
	guint32 number;
	gchar *check, *end;
	gboolean is_uint32;

	g_assert (reply);

	table = g_hash_table_new (g_str_hash, g_str_equal);
	res = decode_property_variant_array (reply, get_attributes_foreach, table);
	if (res == GNOME_KEYRING_RESULT_OK) {
		g_hash_table_iter_init (&iter, table);
		while (g_hash_table_iter_next (&iter, (gpointer*)&name, (gpointer*)&value)) {
			g_assert (name && value);

			/* Hide these gnome-keyring internal attributes */
			if (g_str_has_prefix (name, "gkr:"))
				continue;

			/*
			 * Figure out the attribute type. In the secrets service
			 * all attributes have string values. The daemon will
			 * set a special compat attribute to indicate to us
			 * whether this was a uint32
			 */
			check = g_strdup_printf ("gkr:compat:uint32:%s", name);
			is_uint32 = g_hash_table_lookup (table, check) != NULL;
			g_free (check);

			if (is_uint32) {
				number = strtoul (value, &end, 10);
				if (end && end[0] == '\0')
					gnome_keyring_attribute_list_append_uint32 (attrs, name, number);
				else
					is_uint32 = FALSE;
			}

			if (!is_uint32)
				gnome_keyring_attribute_list_append_string (attrs, name, value);
		}
	}

	g_hash_table_destroy (table);
	return res;
}

static void
get_attributes_reply (Operation *op, DBusMessage *reply)
{
	GnomeKeyringOperationGetAttributesCallback callback;
	GnomeKeyringResult res;
	GnomeKeyringAttributeList *attrs;

	g_assert (op->user_callback_type == CALLBACK_GET_ATTRIBUTES);
	callback = op->user_callback;

	attrs = gnome_keyring_attribute_list_new ();
	res = get_attributes_decode (reply, attrs);
	(*callback) (res, res == GNOME_KEYRING_RESULT_OK ? attrs : NULL, op->user_data);
	gnome_keyring_attribute_list_free (attrs);
}

/**
 * gnome_keyring_item_get_attributes:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Get all the attributes for an item.
 *
 * A #GnomeKeyringAttributeList will be passed to the @callback. This list will
 * be freed after @callback returns.
 *
 * For a synchronous version of this function see gnome_keyring_item_get_attributes_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_get_attributes (const char                                 *keyring,
                                   guint32                                     id,
                                   GnomeKeyringOperationGetAttributesCallback  callback,
                                   gpointer                                    data,
                                   GDestroyNotify                              destroy_data)
{
	DBusMessage *req;
	Operation *op;
	gchar *path;

	path = encode_keyring_item_id (keyring, id);
	g_return_val_if_fail (path, NULL);

	req = prepare_property_get (path, ITEM_INTERFACE, "Attributes");

	op = operation_new (callback, CALLBACK_GET_ATTRIBUTES, data, destroy_data);
	op->reply_handler = get_attributes_reply;
	start_operation (op, req);

	dbus_message_unref (req);
	operation_unref (op);
	g_free (path);
	return op;
}

/**
 * gnome_keyring_item_get_attributes_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @attributes: The location to return a pointer to the attribute list.
 *
 * Get all attributes for an item.
 *
 * A #GnomeKeyringAttributeList will be returned in @attributes. This should be
 * freed using gnome_keyring_attribute_list_free().
 *
 * For an asynchronous version of this function see gnome_keyring_item_get_attributes().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_item_get_attributes_sync (const char                 *keyring,
                                        guint32                     id,
                                        GnomeKeyringAttributeList **attributes)
{
	GnomeKeyringAttributeList *attrs;
	DBusMessage *req, *reply;
	GnomeKeyringResult res;
	gchar *path;

	g_return_val_if_fail (attributes, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);

	path = encode_keyring_item_id (keyring, id);
	g_return_val_if_fail (path, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	req = prepare_property_get (path, ITEM_INTERFACE, "Attributes");
	g_return_val_if_fail (req, BROKEN);
	g_free (path);

	res = send_to_service_and_simple_block (req, &reply);
	dbus_message_unref (req);

	if (res == GNOME_KEYRING_RESULT_OK) {
		attrs = gnome_keyring_attribute_list_new ();
		res = get_attributes_decode (reply, attrs);
		if (res != GNOME_KEYRING_RESULT_OK)
			*attributes = attrs;
		else
			gnome_keyring_attribute_list_free (attrs);
	}

	dbus_message_unref (reply);
	return res;
}

/**
 * gnome_keyring_item_set_attributes:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @attributes: The full list of attributes to set on the item.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Set all the attributes for an item. This will replace any previous attributes
 * set on the item.
 *
 * For a synchronous version of this function see gnome_keyring_item_set_attributes_sync().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_set_attributes (const char                                 *keyring,
                                   guint32                                     id,
                                   GnomeKeyringAttributeList                  *attributes,
                                   GnomeKeyringOperationDoneCallback           callback,
                                   gpointer                                    data,
                                   GDestroyNotify                              destroy_data)
{
#if 0
	GnomeKeyringOperation *op;

	op = operation_new (FALSE, callback, CALLBACK_DONE, data, destroy_data);

	if (!gkr_proto_encode_set_attributes (&op->send_buffer, keyring, id,
	                                      attributes)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = standard_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_item_set_attributes_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @attributes: The full list of attributes to set on the item.
 *
 * Set all the attributes for an item. This will replace any previous attributes
 * set on the item.
 *
 * For an asynchronous version of this function see gnome_keyring_item_set_attributes().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_item_set_attributes_sync (const char                *keyring,
                                        guint32                    id,
                                        GnomeKeyringAttributeList *attributes)
{
#if 0
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	if (!gkr_proto_encode_set_attributes (&send, keyring, id, attributes)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	egg_buffer_uninit (&receive);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;

}

/**
 * gnome_keyring_item_get_acl:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 *
 * Deprecated: Never returns any ACL values.
 **/
gpointer
gnome_keyring_item_get_acl (const char                                 *keyring,
                            guint32                                     id,
                            GnomeKeyringOperationGetListCallback        callback,
                            gpointer                                    data,
                            GDestroyNotify                              destroy_data)
{
	Operation *op;
	op = operation_new (callback, CALLBACK_GET_ACL, data, destroy_data);
	operation_schedule_completed (op, GNOME_KEYRING_RESULT_OK);
	return op;
}

/**
 * gnome_keyring_item_get_acl_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @acl: The location to return a pointer to the access control list.
 *
 * Return value: Always %GNOME_KEYRING_RESULT_OK.
 *
 * Deprecated: Never returns any acls.
 **/
GnomeKeyringResult
gnome_keyring_item_get_acl_sync (const char  *keyring,
                                 guint32      id,
                                 GList      **acl)
{
	g_return_val_if_fail (acl, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	*acl = NULL;
	return GNOME_KEYRING_RESULT_OK;
}

/**
 * gnome_keyring_item_set_acl:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @acl: The access control list to set on the item.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 *
 * Deprecated: This function no longer has any effect.
 **/
gpointer
gnome_keyring_item_set_acl (const char                                 *keyring,
                            guint32                                     id,
                            GList                                      *acl,
                            GnomeKeyringOperationDoneCallback           callback,
                            gpointer                                    data,
                            GDestroyNotify                              destroy_data)
{
	Operation *op;
	op = operation_new (callback, CALLBACK_DONE, data, destroy_data);
	operation_schedule_completed (op, GNOME_KEYRING_RESULT_OK);
	return op;
}

/**
 * gnome_keyring_item_set_acl_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @acl: The access control list to set on the item.
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 *
 * Deprecated: This function no longer has any effect.
 **/
GnomeKeyringResult
gnome_keyring_item_set_acl_sync (const char *keyring,
                                 guint32     id,
                                 GList      *acl)
{
	return GNOME_KEYRING_RESULT_OK;
}

/**
 * gnome_keyring_item_grant_access_rights:
 * @keyring: The keyring name, or NULL for the default keyring.
 * @display_name: The display name for the application, as returned by g_get_application_name().
 * @full_path: The full filepath to the application.
 * @id: The id of the item to grant access to.
 * @rights: The type of rights to grant.
 * @callback: Callback which is called when the operation completes
 * @data: Data to be passed to callback
 * @destroy_data: Function to be called when data is no longer needed.
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 * Since: 2.20
 *
 * Deprecated: This function no longer has any effect.
 **/
gpointer
gnome_keyring_item_grant_access_rights (const gchar *keyring,
                                        const gchar *display_name,
                                        const gchar *full_path,
                                        const guint32 id,
                                        const GnomeKeyringAccessType rights,
                                        GnomeKeyringOperationDoneCallback callback,
                                        gpointer data,
                                        GDestroyNotify destroy_data)
{
	Operation *op;
	op = operation_new (callback, CALLBACK_DONE, data, destroy_data);
	operation_schedule_completed (op, GNOME_KEYRING_RESULT_OK);
	return op;
}

/**
 * gnome_keyring_item_grant_access_rights_sync:
 * @keyring: The keyring name, or NULL for the default keyring.
 * @display_name: The display name for the application, as returned by g_get_application_name().
 * @full_path: The full filepath to the application.
 * @id: The id of the item to grant access to.
 * @rights: The type of rights to grant.
 *
 * Will grant the application access rights to the item, provided
 * callee has write access to said item.
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 *
 * Deprecated: This function no longer has any effect.
 **/
GnomeKeyringResult
gnome_keyring_item_grant_access_rights_sync (const char                   *keyring,
                                             const char                   *display_name,
                                             const char                   *full_path,
                                             const guint32                id,
                                             const GnomeKeyringAccessType rights)
{
	return GNOME_KEYRING_RESULT_OK;
}

/* ------------------------------------------------------------------------------
 * NETWORK PASSWORD APIS
 */

/**
 * SECTION:gnome-keyring-network
 * @title: Network Passwords
 * @short_description: Saving of network passwords.
 *
 * Networks passwords are a simple way of saving passwords associated with a
 * certain user/server/protocol and other fields.
 **/

#if 0
struct FindNetworkPasswordInfo {
	GnomeKeyringOperationGetListCallback callback;
	gpointer                             data;
	GDestroyNotify                       destroy_data;
};

static void
free_find_network_password_info (struct FindNetworkPasswordInfo *info)
{
	if (info->destroy_data != NULL) {
		info->destroy_data (info->data);
	}
	g_free (info);
}

static GList *
found_list_to_nework_password_list (GList *found_list)
{
	GnomeKeyringNetworkPasswordData *data;
	GnomeKeyringFound *found;
	GnomeKeyringAttribute *attributes;
	GList *result, *l;
	int i;

	result = NULL;
	for (l = found_list; l != NULL; l = l->next) {
		found = l->data;

		data = g_new0 (GnomeKeyringNetworkPasswordData, 1);

		result = g_list_prepend (result, data);

		data->keyring = g_strdup (found->keyring);
		data->item_id = found->item_id;
		data->password = gnome_keyring_memory_strdup (found->secret);

		attributes = (GnomeKeyringAttribute *) found->attributes->data;
		for (i = 0; i < found->attributes->len; i++) {
			if (strcmp (attributes[i].name, "user") == 0 &&
			    attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->user = g_strdup (attributes[i].value.string);
			} else if (strcmp (attributes[i].name, "domain") == 0 &&
				   attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->domain = g_strdup (attributes[i].value.string);
			} else if (strcmp (attributes[i].name, "server") == 0 &&
				   attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->server = g_strdup (attributes[i].value.string);
			} else if (strcmp (attributes[i].name, "object") == 0 &&
				   attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->object = g_strdup (attributes[i].value.string);
			} else if (strcmp (attributes[i].name, "protocol") == 0 &&
				   attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->protocol = g_strdup (attributes[i].value.string);
			} else if (strcmp (attributes[i].name, "authtype") == 0 &&
				   attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->authtype = g_strdup (attributes[i].value.string);
			} else if (strcmp (attributes[i].name, "port") == 0 &&
				   attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32) {
				data->port = attributes[i].value.integer;
			}
		}
	}

	return g_list_reverse (result);
}
#endif

/**
 * gnome_keyring_network_password_free:
 * @data: A #GnomeKeyringNetworkPasswordData pointer.
 *
 * Free a network password data pointer. If %NULL is passed in,
 * nothing happens.
 **/
void
gnome_keyring_network_password_free (GnomeKeyringNetworkPasswordData *data)
{
	if (!data)
		return;

	g_free (data->keyring);
	g_free (data->protocol);
	g_free (data->server);
	g_free (data->object);
	g_free (data->authtype);
	g_free (data->user);
	g_free (data->domain);
	gnome_keyring_free_password (data->password);

	g_free (data);
}

/**
 * gnome_keyring_network_password_list_free:
 * @list: A list of #GnomeKeyringNetworkPasswordData pointers.
 *
 * Free a list of network password data.
 **/
void
gnome_keyring_network_password_list_free (GList *list)
{
	g_list_foreach (list, (GFunc)gnome_keyring_network_password_free, NULL);
	g_list_free (list);
}

#if 0
static void
find_network_password_callback (GnomeKeyringResult result,
                                GList             *list,
                                gpointer           data)
{
	struct FindNetworkPasswordInfo *info;
	GList *data_list;

	info = data;

	data_list = NULL;
	if (result == GNOME_KEYRING_RESULT_OK) {
		data_list = found_list_to_nework_password_list (list);
	}
	info->callback (result, data_list, info->data);
	gnome_keyring_network_password_list_free (data_list);
	return;
}

static GnomeKeyringAttributeList *
make_attribute_list_for_network_password (const char                            *user,
                                          const char                            *domain,
                                          const char                            *server,
                                          const char                            *object,
                                          const char                            *protocol,
                                          const char                            *authtype,
                                          guint32                                port)
{
	GnomeKeyringAttributeList *attributes;

	attributes = g_array_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute));

	if (user != NULL) {
		gnome_keyring_attribute_list_append_string (attributes, "user", user);
	}
	if (domain != NULL) {
		gnome_keyring_attribute_list_append_string (attributes, "domain", domain);
	}
	if (server != NULL) {
		gnome_keyring_attribute_list_append_string (attributes, "server", server);
	}
	if (object != NULL) {
		gnome_keyring_attribute_list_append_string (attributes, "object", object);
	}
	if (protocol != NULL) {
		gnome_keyring_attribute_list_append_string (attributes, "protocol", protocol);
	}
	if (authtype != NULL) {
		gnome_keyring_attribute_list_append_string (attributes, "authtype", authtype);
	}
	if (port != 0) {
		gnome_keyring_attribute_list_append_uint32 (attributes, "port", port);
	}
	return attributes;
}
#endif

/**
 * gnome_keyring_find_network_password:
 * @user: The user name or %NULL for any user.
 * @domain: The domain name %NULL for any domain.
 * @server: The server or %NULL for any server.
 * @object: The remote object or %NULL for any object.
 * @protocol: The network protorol or %NULL for any protocol.
 * @authtype: The authentication type or %NULL for any type.
 * @port: The network port or zero for any port.
 * @callback: Callback which is called when the operation completes
 * @data: Data to be passed to callback
 * @destroy_data: Function to be called when data is no longer needed.
 *
 * Find a previously stored network password. Searches all keyrings.
 *
 * A %GList of #GnomeKeyringNetworkPasswordData structures are passed to the
 * @callback. The list and structures are freed after the callback returns.
 *
 * The user may have been prompted to unlock necessary keyrings, and user will
 * have been prompted for access to the items if needed.
 *
 * Network passwords are items with the item type %GNOME_KEYRING_ITEM_NETWORK_PASSWORD
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_find_network_password      (const char                            *user,
                                          const char                            *domain,
                                          const char                            *server,
                                          const char                            *object,
                                          const char                            *protocol,
                                          const char                            *authtype,
                                          guint32                                port,
                                          GnomeKeyringOperationGetListCallback   callback,
                                          gpointer                               user_data,
                                          GDestroyNotify                         destroy_data)
{
#if 0
	GnomeKeyringAttributeList *attributes;
	gpointer request;
	struct FindNetworkPasswordInfo *info;

	info = g_new0 (struct FindNetworkPasswordInfo, 1);
	info->callback = callback;
	info->data = user_data;
	info->destroy_data = destroy_data;

	attributes = make_attribute_list_for_network_password (user,
	                                                       domain,
	                                                       server,
	                                                       object,
	                                                       protocol,
	                                                       authtype,
	                                                       port);

	request = gnome_keyring_find_items (GNOME_KEYRING_ITEM_NETWORK_PASSWORD,
	                                    attributes,
	                                    find_network_password_callback,
	                                    info,
	                                    (GDestroyNotify)free_find_network_password_info);

	gnome_keyring_attribute_list_free (attributes);
	return request;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_find_network_password_sync:
 * @user: The user name or %NULL.
 * @domain: The domain name %NULL.
 * @server: The server or %NULL.
 * @object: The remote object or %NULL.
 * @protocol: The network protorol or %NULL.
 * @authtype: The authentication type or %NULL.
 * @port: The network port or zero.
 * @results: A location to return a %GList of #GnomeKeyringNetworkPasswordData pointers.
 *
 * Find a previously stored network password. Searches all keyrings.
 *
 * A %GList of #GnomeKeyringNetworkPasswordData structures are returned in the
 * @out_list argument. The list should be freed with gnome_keyring_network_password_list_free()
 *
 * The user may have been prompted to unlock necessary keyrings, and user will
 * have been prompted for access to the items if needed.
 *
 * Network passwords are items with the item type %GNOME_KEYRING_ITEM_NETWORK_PASSWORD
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_find_network_password_sync (const char                            *user,
                                          const char                            *domain,
                                          const char                            *server,
                                          const char                            *object,
                                          const char                            *protocol,
                                          const char                            *authtype,
                                          guint32                                port,
                                          GList                                **results)
{
#if 0
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringResult result;
	GList *found;

	*results = NULL;
	attributes = make_attribute_list_for_network_password (user,
	                                                       domain,
	                                                       server,
	                                                       object,
	                                                       protocol,
	                                                       authtype,
	                                                       port);

	result = gnome_keyring_find_items_sync (GNOME_KEYRING_ITEM_NETWORK_PASSWORD,
	                                        attributes,
	                                        &found);

	gnome_keyring_attribute_list_free (attributes);

	if (result == GNOME_KEYRING_RESULT_OK) {
		*results = found_list_to_nework_password_list (found);
		gnome_keyring_found_list_free (found);
	}

	return result;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

#if 0
static char *
get_network_password_display_name (const char *user,
                                   const char *server,
                                   const char *object,
                                   guint32  port)
{
	GString *s;
	char *name;

	if (server != NULL) {
		s = g_string_new (NULL);
		if (user != NULL) {
			g_string_append_printf (s, "%s@", user);
		}
		g_string_append (s, server);
		if (port != 0) {
			g_string_append_printf (s, ":%d", port);
		}
		if (object != NULL) {
			g_string_append_printf (s, "/%s", object);
		}
		name = g_string_free (s, FALSE);
	} else {
		name = g_strdup ("network password");
	}
	return name;
}
#endif


/**
 * gnome_keyring_set_network_password:
 * @keyring: The keyring to store the password in, or %NULL for the default keyring.
 * @user: The user name or %NULL.
 * @domain: The domain name %NULL.
 * @server: The server or %NULL.
 * @object: The remote object or %NULL.
 * @protocol: The network protorol or %NULL.
 * @authtype: The authentication type or %NULL.
 * @port: The network port or zero.
 * @password: The password to store, must not be %NULL.
 * @callback: Callback which is called when the operation completes
 * @data: Data to be passed to callback
 * @destroy_data: Function to be called when data is no longer needed.
 *
 * Store a network password.
 *
 * If an item already exists for with this network info (ie: user, server etc...)
 * then it will be updated.
 *
 * Whether a new item is created or not, id of the item will be passed to
 * the @callback.
 *
 * Network passwords are items with the item type %GNOME_KEYRING_ITEM_NETWORK_PASSWORD
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_set_network_password      (const char                            *keyring,
                                         const char                            *user,
                                         const char                            *domain,
                                         const char                            *server,
                                         const char                            *object,
                                         const char                            *protocol,
                                         const char                            *authtype,
                                         guint32                                port,
                                         const char                            *password,
                                         GnomeKeyringOperationGetIntCallback    callback,
                                         gpointer                               data,
                                         GDestroyNotify                         destroy_data)
{
#if 0
	GnomeKeyringAttributeList *attributes;
	gpointer req;
	char *name;

	name = get_network_password_display_name (user, server, object, port);

	attributes = make_attribute_list_for_network_password (user,
	                                                       domain,
	                                                       server,
	                                                       object,
	                                                       protocol,
	                                                       authtype,
	                                                       port);

	req = gnome_keyring_item_create (keyring,
	                                 GNOME_KEYRING_ITEM_NETWORK_PASSWORD,
	                                 name,
	                                 attributes,
	                                 password,
	                                 TRUE,
	                                 callback, data, destroy_data);

	gnome_keyring_attribute_list_free (attributes);
	g_free (name);

	return req;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_set_network_password_sync:
 * @keyring: The keyring to store the password in, or %NULL for the default keyring.
 * @user: The user name or %NULL.
 * @domain: The domain name %NULL.
 * @server: The server or %NULL.
 * @object: The remote object or %NULL.
 * @protocol: The network protorol or %NULL.
 * @authtype: The authentication type or %NULL.
 * @port: The network port or zero.
 * @password: The password to store, must not be %NULL.
 * @item_id: A location to store the resulting item's id.
 *
 * Store a network password.
 *
 * If an item already exists for with this network info (ie: user, server etc...)
 * then it will be updated.
 *
 * The created or updated item id will be returned in @item_id.
 *
 * Network passwords are items with the item type %GNOME_KEYRING_ITEM_NETWORK_PASSWORD
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_set_network_password_sync (const char                            *keyring,
                                         const char                            *user,
                                         const char                            *domain,
                                         const char                            *server,
                                         const char                            *object,
                                         const char                            *protocol,
                                         const char                            *authtype,
                                         guint32                                port,
                                         const char                            *password,
                                         guint32                               *item_id)
{
#if 0
	GnomeKeyringAttributeList *attributes;
	char *name;
	GnomeKeyringResult res;

	name = get_network_password_display_name (user, server, object, port);
	attributes = make_attribute_list_for_network_password (user,
	                                                       domain,
	                                                       server,
	                                                       object,
	                                                       protocol,
	                                                       authtype,
	                                                       port);

	res = gnome_keyring_item_create_sync (keyring,
	                                      GNOME_KEYRING_ITEM_NETWORK_PASSWORD,
	                                      name,
	                                      attributes,
	                                      password,
	                                      TRUE,
	                                      item_id);

	gnome_keyring_attribute_list_free (attributes);
	g_free (name);

	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

/* ------------------------------------------------------------------------------
 * SIMPLE PASSWORD APIS
 */

/**
 * SECTION:gnome-keyring-password
 * @title: Simple Password Storage
 * @short_description: Store and lookup passwords with a set of attributes.
 *
 * This is a simple API for storing passwords and retrieving passwords in the keyring.
 *
 * Each password is associated with a set of attributes. Attribute values can be either
 * strings or unsigned integers.
 *
 * The names and types of allowed attributes for a given password are defined with a
 * schema. Certain schemas are predefined such as %GNOME_KEYRING_NETWORK_PASSWORD.
 * Additional schemas can be defined via the %GnomeKeyringPasswordSchema structure.
 *
 * Each function accepts a variable list of attributes names and their values.
 * Include a %NULL to terminate the list of attributes.
 *
 * <example>
 * <title>Passing attributes to the functions</title>
 * <programlisting>
 *   res = gnome_keyring_delete_password_sync (GNOME_KEYRING_NETWORK_PASSWORD,
 *                                             "user", "me",        // A string attribute
 *                                             "server, "example.gnome.org",
 *                                             "port", "8080",      // An integer attribute
 *                                             NULL);
 * </programlisting></example>
 **/

/**
 * GnomeKeyringPasswordSchema:
 *
 * Describes a password schema. Often you'll want to use a predefined schema such
 * as %GNOME_KEYRING_NETWORK_PASSWORD.
 *
 * <para>
 * The last attribute name in a schema must be %NULL.
 *
 * <programlisting>
 *   GnomeKeyringPasswordSchema my_schema = {
 *       GNOME_KEYRING_ITEM_GENERIC_SECRET,
 *       {
 *            { "string-attr", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
 *            { "uint-attr", GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32 },
 *            { NULL, 0 }
 *       }
 *   };
 * </programlisting>
 * </para>
 **/

static const GnomeKeyringPasswordSchema network_password_schema = {
	GNOME_KEYRING_ITEM_NETWORK_PASSWORD,
	{
		{  "user", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
		{  "domain", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
		{  "object", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
		{  "protocol", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
		{  "port", GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32 },
		{  "server", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
		{  "NULL", 0 },
	}
};

/**
 * GNOME_KEYRING_NETWORK_PASSWORD:
 *
 * <para>
 * A predefined schema for network paswsords. It contains the following attributes:
 * </para>
 * <itemizedlist>
 * <listitem>user: A string for the user login.</listitem>
 * <listitem>server: The server being connected to.</listitem>
 * <listitem>protocol: The protocol used to access the server, such as 'http' or 'smb'</listitem>
 * <listitem>domain: A realm or domain, such as a Windows login domain.</listitem>
 * <listitem>port: The network port to used to connect to the server.</listitem>
 * </itemizedlist>
 **/

/* Declared in gnome-keyring.h */
const GnomeKeyringPasswordSchema *GNOME_KEYRING_NETWORK_PASSWORD = &network_password_schema;

/**
 * GNOME_KEYRING_DEFAULT:
 *
 * <para>
 * The default keyring.
 * </para>
 **/

/**
 * GNOME_KEYRING_SESSION:
 *
 * <para>
 * A keyring only stored in memory.
 * </para>
 **/

#if 0
static GnomeKeyringAttributeList*
schema_attribute_list_va (const GnomeKeyringPasswordSchema *schema, va_list args)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttributeType type;
	GnomeKeyringAttribute attribute;
	gboolean type_found;
	char *str;
	guint32 i, val;

	attributes = g_array_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute));

	while ((attribute.name = va_arg (args, char *)) != NULL) {

		type_found = FALSE;
		for (i = 0; i < G_N_ELEMENTS (schema->attributes); ++i) {
			if (!schema->attributes[i].name)
				break;
			if (strcmp (schema->attributes[i].name, attribute.name) == 0) {
				type_found = TRUE;
				type = schema->attributes[i].type;
				break;
			}
		}

		if (!type_found) {
			g_warning ("The password attribute '%s' was not found in the password schema.", attribute.name);
			g_array_free (attributes, TRUE);
			return NULL;
		}

		attribute.type = type;
		switch (type) {
		case GNOME_KEYRING_ATTRIBUTE_TYPE_STRING:
			str = va_arg (args, char *);
			attribute.value.string = str;
			g_array_append_val (attributes, attribute);
			break;
		case GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32:
			val = va_arg (args, guint32);
			attribute.value.integer = val;
			g_array_append_val (attributes, attribute);
			break;
		default:
			g_warning ("The password attribute '%s' has an invalid type in the password schema.", attribute.name);
			g_array_free (attributes, TRUE);
			return NULL;
		}
	}

	return attributes;
}
#endif

/**
 * gnome_keyring_store_password:
 * @schema: The password schema.
 * @keyring: The keyring to store the password in. Specify %NULL for the default keyring.
 *           Use %GNOME_KEYRING_SESSION to store the password in memory only.
 * @display_name: A human readable description of what the password is for.
 * @password: The password to store.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 * @...: The variable argument list should contain pairs of a) The attribute name as a null
 *       terminated string, followed by b) attribute value, either a character string,
 *       or 32-bit unsigned int, as defined in the password @schema. The list of attribtues
 *       should be terminated with a %NULL.
 *
 * Store a password associated with a given set of attributes.
 *
 * Attributes which identify this password must be passed as additional
 * arguments. Attributes passed must be defined in the schema.
 *
 * If a password exists in the keyring that already has all the same arguments,
 * then the password will be updated.
 *
 * Another more complex way to create a keyring item is using gnome_keyring_item_create().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 * Since: 2.22
 **/
gpointer
gnome_keyring_store_password (const GnomeKeyringPasswordSchema* schema, const gchar *keyring,
                              const gchar *display_name, const gchar *password,
                              GnomeKeyringOperationDoneCallback callback,
                              gpointer data, GDestroyNotify destroy_data, ...)
{
#if 0
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringOperation *op;
	va_list args;

	va_start (args, destroy_data);
	attributes = schema_attribute_list_va (schema, args);
	va_end (args);

	op = operation_new (FALSE, callback, CALLBACK_DONE, data, destroy_data);

	/* Automatically secures buffer */
	if (!attributes || !attributes->len ||
	    !gkr_proto_encode_create_item (&op->send_buffer, keyring, display_name,
	                                   attributes, password, schema->item_type, TRUE))
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);

	op->reply_handler = standard_reply;
	g_array_free (attributes, TRUE);
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_store_password_sync:
 * @schema: The password schema.
 * @keyring: The keyring to store the password in. Specify %NULL for the default keyring.
 *           Use %GNOME_KEYRING_SESSION to store the password in memory only.
 * @display_name: A human readable description of what the password is for.
 * @password: The password to store.
 * @...: The variable argument list should contain pairs of a) The attribute name as a null
 *       terminated string, followed by b) attribute value, either a character string,
 *       or 32-bit unsigned int, as defined in the password @schema. The list of attribtues
 *       should be terminated with a %NULL.
 *
 * Store a password associated with a given set of attributes.
 *
 * Attributes which identify this password must be passed as additional
 * arguments. Attributes passed must be defined in the schema.
 *
 * This function may block for an unspecified period. If your application must
 * remain responsive to the user, then use gnome_keyring_store_password().
 *
 * If a password exists in the keyring that already has all the same arguments,
 * then the password will be updated.
 *
 * Another more complex way to create a keyring item is using
 * gnome_keyring_item_create_sync().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 * Since: 2.22
 **/
GnomeKeyringResult
gnome_keyring_store_password_sync (const GnomeKeyringPasswordSchema* schema, const gchar *keyring,
                                   const gchar *display_name, const gchar *password, ...)
{
#if 0
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringResult res;
	guint32 item_id;
	va_list args;

	va_start (args, password);
	attributes = schema_attribute_list_va (schema, args);
	va_end (args);

	if (!attributes || !attributes->len)
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;

	res = gnome_keyring_item_create_sync (keyring, schema->item_type, display_name,
	                                      attributes, password, TRUE, &item_id);

	g_array_free (attributes, TRUE);
	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

#if 0
static gboolean
find_password_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetStringCallback callback;
	GList *found_items;
	const gchar *password;

	g_assert (op->user_callback_type == CALLBACK_GET_STRING);
	callback = op->user_callback;

	if (!gkr_proto_decode_find_reply (&op->receive_buffer, &result, &found_items)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		password = NULL;
		if (found_items)
			password = ((GnomeKeyringFound*)(found_items->data))->secret;
		(*callback) (result, password, op->user_data);
		gnome_keyring_found_list_free (found_items);
	}

	/* Operation is done */
	return TRUE;
}
#endif

/**
 * gnome_keyring_find_password:
 * @schema: The password schema.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 * @...: The variable argument list should contain pairs of a) The attribute name as a null
 *       terminated string, followed by b) attribute value, either a character string,
 *       or 32-bit unsigned int, as defined in the password @schema. The list of attribtues
 *       should be terminated with a %NULL.
 *
 * Find a password that matches a given set of attributes.
 *
 * Attributes which identify this password must be passed as additional
 * arguments. Attributes passed must be defined in the schema.
 *
 * The string that is passed to @callback is automatically freed when the
 * function returns.
 *
 * Another more complex way to find items in the keyrings is using
 * gnome_keyring_find_items().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 * Since: 2.22
 **/
gpointer
gnome_keyring_find_password (const GnomeKeyringPasswordSchema* schema,
                             GnomeKeyringOperationGetStringCallback callback,
                             gpointer data, GDestroyNotify destroy_data, ...)
{
#if 0
	GnomeKeyringOperation *op;
	GnomeKeyringAttributeList *attributes;
	va_list args;

	op = operation_new (TRUE, callback, CALLBACK_GET_STRING, data, destroy_data);

	va_start (args, destroy_data);
	attributes = schema_attribute_list_va (schema, args);
	va_end (args);

	if (!attributes || !attributes->len ||
	    !gkr_proto_encode_find (&op->send_buffer, schema->item_type, attributes))
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);

	g_array_free (attributes, TRUE);

	op->reply_handler = find_password_reply;
	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_find_password_sync:
 * @schema: The password schema.
 * @password: An address to store password that was found. The password must
 *            be freed with gnome_keyring_free_password().
 * @...: The variable argument list should contain pairs of a) The attribute name as a null
 *       terminated string, followed by b) attribute value, either a character string,
 *       or 32-bit unsigned int, as defined in the password @schema. The list of attribtues
 *       should be terminated with a %NULL.
 *
 * Find a password that matches a given set of attributes.
 *
 * Attributes which identify this password must be passed as additional
 * arguments. Attributes passed must be defined in the schema.
 *
 * This function may block for an unspecified period. If your application must
 * remain responsive to the user, then use gnome_keyring_find_password().
 *
 * Another more complex way to find items in the keyrings is using
 * gnome_keyring_find_items_sync().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 * Since: 2.22
 **/
GnomeKeyringResult
gnome_keyring_find_password_sync(const GnomeKeyringPasswordSchema* schema, gchar **password, ...)
{
#if 0
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringResult res;
	GnomeKeyringFound *f;
	GList* found = NULL;
	va_list args;

	va_start (args, password);
	attributes = schema_attribute_list_va (schema, args);
	va_end (args);

	if (!attributes || !attributes->len)
		res = GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	else
		res = gnome_keyring_find_items_sync (schema->item_type, attributes, &found);

	g_array_free (attributes, TRUE);

	if (password && res == GNOME_KEYRING_RESULT_OK) {
		*password = NULL;
		if (g_list_length (found) > 0) {
			f = (GnomeKeyringFound*)(found->data);
			*password = f->secret;
			f->secret = NULL;
		}
	}

	gnome_keyring_found_list_free (found);
	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}

#if 0
typedef struct _DeletePassword {
	GList *found;
	GList *at;
	guint non_session;
	guint deleted;
} DeletePassword;

static void
delete_password_destroy (gpointer data)
{
	DeletePassword *dp = (DeletePassword*)data;
	gnome_keyring_found_list_free (dp->found);
	g_free (dp);
}

static gboolean
delete_password_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationDoneCallback callback;
	GnomeKeyringFound *f;
	DeletePassword *dp;

	g_assert (op->user_callback_type == CALLBACK_DONE);
	callback = op->user_callback;

	dp = op->reply_data;
	g_assert (dp);

	/* The result of the find */
	if (!dp->found) {
		if (!gkr_proto_decode_find_reply (&op->receive_buffer, &result, &dp->found))
			result = GNOME_KEYRING_RESULT_IO_ERROR;

		/* On the first item */
		dp->at = dp->found;

	/* The result of a delete */
	} else {
		if (!gkr_proto_decode_find_reply (&op->receive_buffer, &result, &dp->found))
			result = GNOME_KEYRING_RESULT_IO_ERROR;

		++dp->deleted;
	}

	/* Stop on any failure */
	if (result != GNOME_KEYRING_RESULT_OK) {
		(*callback) (result, op->user_data);
		return TRUE; /* Operation is done */
	}

	/* Iterate over list and find next item to delete */
	while (dp->at) {
		f = (GnomeKeyringFound*)(dp->at->data);
		dp->at = g_list_next (dp->at);

		/* If not an item in the session keyring ... */
		if (!f->keyring || strcmp (f->keyring, GNOME_KEYRING_SESSION) != 0) {

			++dp->non_session;

			/* ... then we only delete one of those */
			if (dp->non_session > 1)
				continue;
		}

		/* Reset the operation into a delete */
		start_and_take_operation (op);

		egg_buffer_reset (&op->send_buffer);
		if (!gkr_proto_encode_op_string_int (&op->send_buffer, GNOME_KEYRING_OP_DELETE_ITEM,
		                                     f->keyring, f->item_id)) {
			/*
			 * This would happen if the server somehow sent us an invalid
			 * keyring and item_id. Very unlikely, and it seems this is
			 * the best error code in this case.
			 */
			(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, op->user_data);
			return TRUE;
		}

		/*
		 * The delete operation is ready for processing, by returning
		 * FALSE we indicate that the operation is not complete.
		 */
		return FALSE;
	}

	/* Nothing more to find */
	g_assert (!dp->at);

	/* Operation is done */
	(*callback) (dp->deleted > 0 ? GNOME_KEYRING_RESULT_OK : GNOME_KEYRING_RESULT_NO_MATCH, op->user_data);
	return TRUE;
}
#endif

/**
 * gnome_keyring_delete_password:
 * @schema: The password schema.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 * @...: The variable argument list should contain pairs of a) The attribute name as a null
 *       terminated string, followed by b) attribute value, either a character string,
 *       or 32-bit unsigned int, as defined in the password @schema. The list of attribtues
 *       should be terminated with a %NULL.
 *
 * Delete a password that matches a given set of attributes.
 *
 * Attributes which identify this password must be passed as additional
 * arguments. Attributes passed must be defined in the schema.
 *
 * Another more complex way to find items in the keyrings is using
 * gnome_keyring_item_delete().
 *
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 * Since: 2.22
 **/
gpointer
gnome_keyring_delete_password (const GnomeKeyringPasswordSchema* schema,
                               GnomeKeyringOperationDoneCallback callback,
                               gpointer data, GDestroyNotify destroy_data, ...)
{
#if 0
	GnomeKeyringOperation *op;
	GnomeKeyringAttributeList *attributes;
	va_list args;

	op = operation_new (TRUE, callback, CALLBACK_DONE, data, destroy_data);

	va_start (args, destroy_data);
	attributes = schema_attribute_list_va (schema, args);
	va_end (args);
	if (!attributes || !attributes->len ||
	    !gkr_proto_encode_find (&op->send_buffer, schema->item_type, attributes))
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);

	g_array_free (attributes, TRUE);

	op->reply_handler = delete_password_reply;
	op->reply_data = g_new0 (DeletePassword, 1);
	op->destroy_reply_data = delete_password_destroy;

	start_and_take_operation (op);
	return op;
#endif
	g_assert (FALSE && "TODO");
	return NULL;
}

/**
 * gnome_keyring_delete_password_sync:
 * @schema: The password schema.
 * @...: The variable argument list should contain pairs of a) The attribute name as a null
 *       terminated string, followed by b) attribute value, either a character string,
 *       or 32-bit unsigned int, as defined in the password @schema. The list of attribtues
 *       should be terminated with a %NULL.
 *
 * Delete a password that matches a given set of attributes.
 *
 * Attributes which identify this password must be passed as additional
 * arguments. Attributes passed must be defined in the schema.
 *
 * This function may block for an unspecified period. If your application must
 * remain responsive to the user, then use gnome_keyring_delete_password().
 *
 * Another more complex way to find items in the keyrings is using
 * gnome_keyring_item_delete_sync().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or
 * an error result otherwise.
 * Since: 2.22
 **/
GnomeKeyringResult
gnome_keyring_delete_password_sync (const GnomeKeyringPasswordSchema* schema, ...)
{
#if 0
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringResult res;
	GnomeKeyringFound *f;
	GList *found, *l;
	va_list args;
	guint non_session;

	va_start (args, schema);
	attributes = schema_attribute_list_va (schema, args);
	va_end (args);

	if (!attributes || !attributes->len)
		res = GNOME_KEYRING_RESULT_BAD_ARGUMENTS;

	/* Find the item(s) in question */
	else
		res = gnome_keyring_find_items_sync (schema->item_type, attributes, &found);

	g_array_free (attributes, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK)
		return res;

	non_session = 0;
	for (l = found; l; l = g_list_next (l)) {
		f = (GnomeKeyringFound*)(l->data);

		/* If not an item in the session keyring ... */
		if (!f->keyring || strcmp (f->keyring, GNOME_KEYRING_SESSION) != 0) {

			++non_session;

			/* ... then we only delete one of those */
			if (non_session > 1)
				continue;
		}

		res = gnome_keyring_item_delete_sync (f->keyring, f->item_id);
		if (res != GNOME_KEYRING_RESULT_OK)
			break;
	}

	gnome_keyring_found_list_free (found);
	return res;
#endif
	g_assert (FALSE && "TODO");
	return 0;
}
