/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-callback.c - run callbacks

   Copyright (C) 2009 Stefan Walter

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

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gnome-keyring.h"
#include "gnome-keyring-private.h"

GkrCallback*
gkr_callback_new (gpointer callback, GkrCallbackType callback_type,
                  gpointer user_data, GDestroyNotify destroy_func)
{
	GkrCallback *cb = g_slice_new (GkrCallback);
	cb->callback = callback;
	cb->destroy_func = destroy_func;
	cb->type = callback_type;
	cb->user_data = user_data;
	return cb;
}

void
gkr_callback_free (gpointer data)
{
	GkrCallback *cb = data;
	if (cb == NULL)
		return;
	if (cb->user_data && cb->destroy_func)
		(cb->destroy_func) (cb->user_data);
	g_slice_free (GkrCallback, cb);
}

typedef void (*OpMsgCallback) (GkrOperation*, DBusMessage*, gpointer);

void
gkr_callback_invoke_op_msg (GkrCallback *cb, GkrOperation *op, DBusMessage *msg)
{
	g_assert (cb);
	g_assert (cb->type == GKR_CALLBACK_OP_MSG);

	cb->type = 0;
	if (cb->callback)
		((OpMsgCallback)(cb->callback)) (op, msg, cb->user_data);
}

void
gkr_callback_invoke_res (GkrCallback *cb, GnomeKeyringResult res)
{
	g_assert (cb);

	/* When successful can only call one kind of callback */
	if (res == GNOME_KEYRING_RESULT_OK) {
		g_assert (cb->type == GKR_CALLBACK_RES);
		cb->type = 0;
		if (cb->callback)
			((GnomeKeyringOperationDoneCallback)cb->callback) (res, cb->user_data);

	/* When failing, we can call anything with a res */
	} else {
		switch (cb->type) {
		case GKR_CALLBACK_RES_STRING:
			gkr_callback_invoke_res_string (cb, res, NULL);
			break;
		case GKR_CALLBACK_RES_UINT:
			gkr_callback_invoke_res_uint (cb, res, 0);
			break;
		case GKR_CALLBACK_RES_LIST:
			gkr_callback_invoke_res_list (cb, res, NULL);
			break;
		case GKR_CALLBACK_RES_KEYRING_INFO:
			gkr_callback_invoke_res_keyring_info (cb, res, NULL);
			break;
		case GKR_CALLBACK_RES_ITEM_INFO:
			gkr_callback_invoke_res_item_info (cb, res, NULL);
			break;
		case GKR_CALLBACK_RES_ATTRIBUTES:
			gkr_callback_invoke_res_attributes (cb, res, NULL);
			break;
		default:
			g_assert_not_reached ();
		}
	}
}

void
gkr_callback_invoke_res_string (GkrCallback *cb, GnomeKeyringResult res,
                                const gchar *value)
{
	g_assert (cb);
	g_assert (cb->type == GKR_CALLBACK_RES_STRING);
	cb->type = 0;
	if (res != GNOME_KEYRING_RESULT_OK)
		value = NULL;
	if (cb->callback)
		((GnomeKeyringOperationGetStringCallback)cb->callback) (res, value, cb->user_data);
}


void
gkr_callback_invoke_res_uint (GkrCallback *cb, GnomeKeyringResult res,
                              guint32 value)
{
	g_assert (cb);
	g_assert (cb->type == GKR_CALLBACK_RES_UINT);
	cb->type = 0;
	if (res != GNOME_KEYRING_RESULT_OK)
		value = 0;
	if (cb->callback)
		((GnomeKeyringOperationGetIntCallback)cb->callback) (res, value, cb->user_data);
}

void
gkr_callback_invoke_res_list (GkrCallback *cb, GnomeKeyringResult res,
                              GList *value)
{
	g_assert (cb);
	g_assert (cb->type == GKR_CALLBACK_RES_LIST);
	cb->type = 0;
	if (res != GNOME_KEYRING_RESULT_OK)
		value = NULL;
	if (cb->callback)
		((GnomeKeyringOperationGetListCallback)cb->callback) (res, value, cb->user_data);
}

void
gkr_callback_invoke_res_keyring_info (GkrCallback *cb, GnomeKeyringResult res,
                                      GnomeKeyringInfo *value)
{
	g_assert (cb);
	g_assert (cb->type == GKR_CALLBACK_RES_KEYRING_INFO);
	cb->type = 0;
	if (res != GNOME_KEYRING_RESULT_OK)
		value = NULL;
	if (cb->callback)
		((GnomeKeyringOperationGetKeyringInfoCallback)cb->callback) (res, value, cb->user_data);

}

void
gkr_callback_invoke_res_item_info (GkrCallback *cb, GnomeKeyringResult res,
                                   GnomeKeyringItemInfo *value)
{
	g_assert (cb);
	g_assert (cb->type == GKR_CALLBACK_RES_ITEM_INFO);
	cb->type = 0;
	if (res != GNOME_KEYRING_RESULT_OK)
		value = NULL;
	if (cb->callback)
		((GnomeKeyringOperationGetItemInfoCallback)cb->callback) (res, value, cb->user_data);
}

void
gkr_callback_invoke_res_attributes (GkrCallback *cb, GnomeKeyringResult res,
                                    GnomeKeyringAttributeList *value)
{
	g_assert (cb);
	g_assert (cb->type == GKR_CALLBACK_RES_ATTRIBUTES);
	cb->type = 0;
	if (res != GNOME_KEYRING_RESULT_OK)
		value = NULL;
	if (cb->callback)
		((GnomeKeyringOperationGetAttributesCallback)cb->callback) (res, value, cb->user_data);

}
