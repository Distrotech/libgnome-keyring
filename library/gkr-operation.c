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
#include "gkr-operation.h"

#include "egg/egg-dbus.h"

static DBusConnection *dbus_connection = NULL;
G_LOCK_DEFINE_STATIC(dbus_connection);

enum {
	INCOMPLETE = -1,
};

struct _GkrOperation {
	/* First two only atomically accessed */
	gint refs;
	gint result;

	DBusConnection *conn;
	DBusPendingCall *pending;

	GQueue callbacks;
	GSList *completed;
};

GkrOperation*
gkr_operation_ref (GkrOperation *op)
{
	g_assert (op);
	g_atomic_int_inc (&op->refs);
	return op;
}

static void
operation_clear_callbacks (GkrOperation *op)
{
	GSList *l;
	g_assert (op);
	while (!g_queue_is_empty (&op->callbacks))
		gkr_callback_free (g_queue_pop_head (&op->callbacks));
	g_queue_clear (&op->callbacks);
	for (l = op->completed; l; l = g_slist_next (l))
		gkr_callback_free (l->data);
	g_slist_free (op->completed);
	op->completed = NULL;
}

void
gkr_operation_unref (gpointer data)
{
	GkrOperation *op = data;

	if (!op)
		return;

	if (!g_atomic_int_dec_and_test (&op->refs))
		return;

	if (op->pending) {
		dbus_pending_call_cancel (op->pending);
		dbus_pending_call_unref (op->pending);
		op->pending = NULL;
	}

	if (op->conn) {
		dbus_connection_unref (op->conn);
		op->conn = NULL;
	}

	operation_clear_callbacks (op);
	g_slice_free (GkrOperation, op);
}

GkrOperation*
gkr_operation_new (gpointer callback, GkrCallbackType callback_type,
                   gpointer user_data, GDestroyNotify destroy_user_data)
{
	GkrOperation *op;

	op = g_slice_new0 (GkrOperation);

	op->refs = 1;
	op->result = INCOMPLETE;
	g_queue_init (&op->callbacks);
	op->completed = NULL;

	gkr_operation_push (op, callback, callback_type, user_data, destroy_user_data);

	return op;
}

GkrCallback*
gkr_operation_push (GkrOperation *op, gpointer callback,
                    GkrCallbackType callback_type,
                    gpointer user_data, GDestroyNotify destroy_func)
{
	GkrCallback *cb = gkr_callback_new (callback, callback_type, user_data, destroy_func);
	g_assert (op);
	g_queue_push_head (&op->callbacks, cb);
	return cb;
}

GkrCallback*
gkr_operation_pop (GkrOperation *op)
{
	GkrCallback *cb;

	g_assert (op);

	cb = g_queue_pop_head (&op->callbacks);
	g_assert (cb);
	op->completed = g_slist_prepend (op->completed, cb);
	return cb;
}

static GnomeKeyringResult
operation_get_result (GkrOperation *op)
{
	GnomeKeyringResult res;
	g_assert (op);
	res = g_atomic_int_get (&op->result);
	g_assert (res != INCOMPLETE);
	return res;
}

static gboolean
operation_set_result (GkrOperation *op, GnomeKeyringResult res)
{
	g_assert (op);
	g_assert (res != INCOMPLETE);
	return g_atomic_int_compare_and_exchange (&op->result, INCOMPLETE, res);
}

static gboolean
on_complete (gpointer data)
{
	GkrOperation *op = data;
	GkrCallback *cb;

	g_assert (op);

	cb = g_queue_pop_tail (&op->callbacks);
	g_assert (cb);

	/* Free all the other callbacks */
	operation_clear_callbacks (op);

	gkr_callback_invoke_res (cb, operation_get_result (op));
	gkr_callback_free (cb);

	return FALSE; /* Don't run idle handler again */
}

void
gkr_operation_complete (GkrOperation *op, GnomeKeyringResult res)
{
	if (operation_set_result (op, res))
		on_complete (op);
}

void
gkr_operation_complete_later (GkrOperation *op, GnomeKeyringResult res)
{
	if (operation_set_result (op, res))
		g_idle_add_full (G_PRIORITY_DEFAULT_IDLE, on_complete,
		                 gkr_operation_ref (op), gkr_operation_unref);
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
callback_with_message (GkrOperation *op, DBusMessage *message)
{
	GkrCallback *cb;

	g_assert (op);
	g_assert (message);

	cb = gkr_operation_pop (op);

	/* A handler that knows what to do with a DBusMessage */
	if (cb->type == GKR_CALLBACK_OP_MSG)
		gkr_callback_invoke_op_msg (cb, op, message);

	/* We hope this is a simple handler, invoke will check */
	else if (!gkr_operation_handle_errors (op, message))
		gkr_callback_invoke_res (cb, GNOME_KEYRING_RESULT_OK);
}

static void
on_pending_call_notify (DBusPendingCall *pending, void *user_data)
{
	GkrOperation *op = user_data;
	DBusMessage *reply;

	g_assert (pending == op->pending);

	reply = dbus_pending_call_steal_reply (pending);
	g_return_if_fail (reply);

	gkr_operation_ref (op);

	dbus_pending_call_unref (op->pending);
	op->pending = NULL;

	callback_with_message (op, reply);
	dbus_message_unref (reply);

	gkr_operation_unref (op);
}

void
gkr_operation_request (GkrOperation *op, DBusMessage *req)
{
	g_assert (op);
	g_assert (req);

	if (!op->conn)
		op->conn = connect_to_service ();

	if (op->conn) {
		g_assert (!op->pending);
		if (!dbus_connection_send_with_reply (op->conn, req, &op->pending, -1))
			g_return_if_reached ();
	}

	if (op->pending)
		dbus_pending_call_set_notify (op->pending, on_pending_call_notify,
		                              gkr_operation_ref (op), gkr_operation_unref);
	else
		gkr_operation_complete_later (op, GNOME_KEYRING_RESULT_IO_ERROR);
}

gboolean
gkr_operation_handle_errors (GkrOperation *op, DBusMessage *reply)
{
	DBusError derr = DBUS_ERROR_INIT;
	GnomeKeyringResult res;

	g_assert (op);
	g_assert (reply);

	if (dbus_set_error_from_message (&derr, reply)) {
		res = handle_error_to_result (&derr, NULL);
		gkr_operation_complete (op, res);
		return TRUE;
	}

	return FALSE;
}

typedef struct _on_prompt_args {
	GkrOperation *op;
	gchar *path;
} on_prompt_args;

static DBusHandlerResult
on_prompt_completed (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	on_prompt_args *args = user_data;
	DBusMessageIter iter;
	dbus_bool_t dismissed;

	g_assert (args);

	if (args->path && dbus_message_has_path (message, args->path) &&
	    dbus_message_is_signal (message, PROMPT_INTERFACE, "Completed")) {

		/* Only one call, even if daemon decides to be strange */
		g_free (args->path);
		args->path = NULL;

		if (!dbus_message_iter_init (message, &iter) ||
		    dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_BOOLEAN)
			g_return_val_if_reached (BROKEN);
		dbus_message_iter_get_basic (&iter, &dismissed);

		/* Remember that invoking these callbacks, can free args */
		if (dismissed)
			gkr_operation_complete (args->op, GNOME_KEYRING_RESULT_CANCELLED);
		else
			callback_with_message (args->op, message);

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void
on_prompt_result (GkrOperation *op, DBusMessage *message, gpointer user_data)
{
	gkr_operation_handle_errors (op, message);
}

static void
on_prompt_free (gpointer data)
{
	on_prompt_args *args = data;
	g_assert (args);
	g_assert (args->op);
	dbus_connection_remove_filter (args->op->conn, on_prompt_completed, args);
	g_free (args->path);
	g_slice_free (on_prompt_args, args);
}

void
gkr_operation_prompt (GkrOperation *op, const gchar *prompt)
{
	on_prompt_args *args;
	DBusMessage *req;

	g_assert (op != NULL);
	g_assert (prompt != NULL);

	/*
	 * args becomes owned by the operation. In addition in its
	 * destroy_func it disconnects the connection filter. So keep
	 * that in mind with the lack of references below.
	 */

	args = g_slice_new (on_prompt_args);
	args->path = g_strdup (prompt);
	args->op = op;
	dbus_connection_add_filter (op->conn, on_prompt_completed, args, NULL);

	req = dbus_message_new_method_call (SECRETS_SERVICE, prompt,
	                                    PROMPT_INTERFACE, "Prompt");

	gkr_operation_push (op, on_prompt_result, GKR_CALLBACK_OP_MSG, args, on_prompt_free);
	gkr_operation_request (op, req);
	dbus_message_unref (req);
}

GnomeKeyringResult
gkr_operation_request_sync (DBusMessage *req, DBusMessage **reply)
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

	*reply = dbus_connection_send_with_reply_and_block (conn, req, -1, &derr);
	if (*reply == NULL)
		res = handle_error_to_result (&derr, "couldn't communicate with daemon");
	else
		res = GNOME_KEYRING_RESULT_OK;

	dbus_connection_unref (conn);
	return res;
}

typedef struct _on_prompt_sync_args {
	const gchar *prompt;
	DBusMessage **signal;
} on_prompt_sync_args;

static DBusHandlerResult
on_prompt_sync_completed (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	on_prompt_sync_args *args = user_data;

	g_assert (args);
	g_assert (args->signal);
	g_assert (args->prompt);

	if (dbus_message_is_signal (message, PROMPT_INTERFACE, "Completed") &&
	    dbus_message_has_path (message, args->prompt)) {
		g_return_val_if_fail (*args->signal == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
		*args->signal = dbus_message_ref (message);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

GnomeKeyringResult
gkr_operation_prompt_sync (const gchar *prompt, DBusMessage **reply)
{
	DBusError derr = DBUS_ERROR_INIT;
	DBusMessage *req, *rep, *signal;
	DBusConnection *conn;
	on_prompt_sync_args args = { prompt, &signal };
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
	dbus_connection_add_filter (conn, on_prompt_sync_completed, &args, NULL);

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

	dbus_connection_remove_filter (conn, on_prompt_sync_completed, &args);
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
