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
#include "gnome-keyring-private.h"

#include "egg/egg-dbus.h"

/**
 * SECTION:gnome-keyring-generic-callbacks
 * @title: Callbacks
 * @short_description: Different callbacks for retrieving async results
 */


static DBusConnection *dbus_connection = NULL;
G_LOCK_DEFINE_STATIC(dbus_connection);

struct _Operation {
	/* First two only atomically accessed */
	gint refs;
	gint result;

	/* Managed by operation calls */
	DBusConnection *conn;
	DBusPendingCall *pending;
	gchar *prompt;

	/* User callback information */
	Callback callback;

	/* May be set by others */
	OperationHandler reply_handler;
	gpointer reply_data;
	GDestroyNotify destroy_reply_data;
};

Operation*
operation_ref (gpointer data)
{
	Operation *op = data;
	g_return_val_if_fail (op, NULL);
	g_atomic_int_inc (&op->refs);
	return op;
}

void
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
	callback_clear (&op->callback);
	if (op->destroy_reply_data != NULL && op->reply_data != NULL)
		(*op->destroy_reply_data) (op->reply_data);
	g_free (op->prompt);
	g_free (op);
}

Operation*
operation_new (gpointer callback, CallbackType callback_type,
               gpointer user_data, GDestroyNotify destroy_user_data)
{
	Operation *op;

	op = g_new0 (Operation, 1);

	op->refs = 1;
	op->result = INCOMPLETE;
	op->callback.type = callback_type;
	op->callback.callback = callback;
	op->callback.user_data = user_data;
	op->callback.destroy_func = destroy_user_data;

	return op;
}

GnomeKeyringResult
operation_get_result (Operation *op)
{
	GnomeKeyringResult res;
	g_assert (op);
	res = g_atomic_int_get (&op->result);
	g_assert (res != INCOMPLETE);
	return res;
}

gboolean
operation_set_result (Operation *op, GnomeKeyringResult res)
{
	g_assert (op);
	g_assert (res != INCOMPLETE);
	return g_atomic_int_compare_and_exchange (&op->result, INCOMPLETE, res);
}

void
operation_set_handler (Operation *op, OperationHandler handler,
                       gpointer user_data, GDestroyNotify destroy_func)
{
	g_assert (op);
	g_assert (!op->reply_handler);
	g_assert (!op->reply_data);
	op->reply_handler = handler;
	op->reply_data = user_data;
	op->destroy_reply_data = destroy_func;
}

static gboolean
on_scheduled_complete (gpointer data)
{
	Operation *op = data;
	callback_no_data (&op->callback, operation_get_result (op));

	/* Don't run idle handler again */
	return FALSE;
}

void
operation_schedule_complete (Operation *op, GnomeKeyringResult result)
{
	if (operation_set_result (op, result))
		g_idle_add_full (G_PRIORITY_DEFAULT_IDLE, on_scheduled_complete,
		                 operation_ref (op), operation_unref);
}

static DBusConnection*
connect_to_service (void)
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

static void
call_reply_handler (Operation *op, DBusMessage *message)
{
	OperationHandler handler;
	gpointer data;
	GDestroyNotify destroy_func;

	/*
	 * Clear this one out, when used once. The reply handler
	 * may set a new reply handler and data.
	 */

	if (operation_get_result (op) != INCOMPLETE)
		return;

	handler = op->reply_handler;
	op->reply_handler = NULL;

	data = op->reply_data;
	op->reply_data = NULL;

	destroy_func = op->destroy_reply_data;
	op->destroy_reply_data = NULL;

	if (handler)
		(handler) (op, &op->callback, message, data);
	else
		callback_no_data (&op->callback, GNOME_KEYRING_RESULT_OK);

	if (data && destroy_func)
		(destroy_func) (data);
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
		call_reply_handler (op, message);
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
			callback_no_data (&op->callback, res);
	} else {

		/*
		 * Are we prompting not prompting, mark as a reply.
		 * When prompting, completed listener will handle reply.
		 */
		if (!op->prompt)
			call_reply_handler (op, reply);
	}

	dbus_message_unref (reply);
}

void
operation_start (Operation *op, DBusMessage *request)
{
	g_assert (op);

	if (!op->conn)
		op->conn = connect_to_service ();

	if (op->conn) {
		if (!dbus_connection_send_with_reply (op->conn, request, &op->pending, -1))
			g_return_if_reached ();
	}

	if (op->pending)
		dbus_pending_call_set_notify (op->pending, on_pending_call_notify,
		                              operation_ref (op), operation_unref);
	else
		operation_schedule_complete (op, GNOME_KEYRING_RESULT_IO_ERROR);
}

void
operation_prompt (Operation *op, const gchar *prompt)
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

	operation_start (op, req);
	dbus_message_unref (req);
}

GnomeKeyringResult
block_request (DBusMessage *req, DBusMessage **reply)
{
	DBusConnection *conn;
	DBusError derr = DBUS_ERROR_INIT;
	GnomeKeyringResult res;

	g_assert (req);
	g_assert (reply);

	conn = connect_to_service ();
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

GnomeKeyringResult
block_prompt (const gchar *prompt, DBusMessage **reply)
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

	conn = connect_to_service ();
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
