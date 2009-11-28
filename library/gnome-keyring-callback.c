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

void
callback_done (Callback *cb, GnomeKeyringResult res)
{
	g_assert (cb);
	g_assert (!cb->called);
	g_assert (cb->type == CALLBACK_DONE);
	cb->called = TRUE;
	if (cb->callback)
		((GnomeKeyringOperationDoneCallback)cb->callback) (res, cb->user_data);
}

void
callback_get_string (Callback *cb, GnomeKeyringResult res, const gchar *string)
{
	g_assert (cb);
	g_assert (!cb->called);
	g_assert (cb->type == CALLBACK_GET_STRING);
	cb->called = TRUE;
	if (res != GNOME_KEYRING_RESULT_OK)
		string = NULL;
	if (cb->callback)
		((GnomeKeyringOperationGetStringCallback)cb->callback) (res, string, cb->user_data);
}

void
callback_get_int (Callback *cb, GnomeKeyringResult res, guint32 val)
{
	g_assert (cb);
	g_assert (!cb->called);
	g_assert (cb->type == CALLBACK_GET_INT);
	cb->called = TRUE;
	if (res != GNOME_KEYRING_RESULT_OK)
		val = 0;
	if (cb->callback)
		((GnomeKeyringOperationGetIntCallback)cb->callback) (res, val, cb->user_data);
}

void
callback_get_list (Callback *cb, GnomeKeyringResult res, GList *list)
{
	g_assert (cb);
	g_assert (!cb->called);
	g_assert (cb->type == CALLBACK_GET_LIST);
	cb->called = TRUE;
	if (res != GNOME_KEYRING_RESULT_OK)
		list = NULL;
	if (cb->callback)
		((GnomeKeyringOperationGetListCallback)cb->callback) (res, list, cb->user_data);
}

void
callback_get_keyring_info (Callback *cb, GnomeKeyringResult res, GnomeKeyringInfo *info)
{
	g_assert (cb);
	g_assert (!cb->called);
	g_assert (cb->type == CALLBACK_GET_KEYRING_INFO);
	cb->called = TRUE;
	if (res != GNOME_KEYRING_RESULT_OK)
		info = NULL;
	if (cb->callback)
		((GnomeKeyringOperationGetKeyringInfoCallback)cb->callback) (res, info, cb->user_data);
}

void
callback_get_item_info (Callback *cb, GnomeKeyringResult res, GnomeKeyringItemInfo *info)
{
	g_assert (cb);
	g_assert (!cb->called);
	g_assert (cb->type == CALLBACK_GET_ITEM_INFO);
	cb->called = TRUE;
	if (cb->callback)
		((GnomeKeyringOperationGetItemInfoCallback)cb->callback) (res, info, cb->user_data);}

void
callback_get_attributes (Callback *cb, GnomeKeyringResult res, GnomeKeyringAttributeList *attrs)
{
	g_assert (cb);
	g_assert (!cb->called);
	g_assert (cb->type == CALLBACK_GET_KEYRING_INFO);
	cb->called = TRUE;
	if (res != GNOME_KEYRING_RESULT_OK)
		attrs = NULL;
	if (cb->callback)
		((GnomeKeyringOperationGetAttributesCallback)cb->callback) (res, attrs, cb->user_data);
}

void
callback_no_data (Callback *cb, GnomeKeyringResult res)
{
	g_assert (cb);

	if (cb->type == CALLBACK_DONE) {
		callback_done (cb, res);
		return;
	}

	/* All these others require data with OK */
	g_assert (res != GNOME_KEYRING_RESULT_OK);

	switch (cb->type) {
	case CALLBACK_GET_STRING:
		callback_get_string (cb, res, NULL);
		break;
	case CALLBACK_GET_INT:
		callback_get_int (cb, res, 0);
		break;
	case CALLBACK_GET_LIST:
		callback_get_list (cb, res, NULL);
		break;
	case CALLBACK_GET_KEYRING_INFO:
		callback_get_keyring_info (cb, res, NULL);
		break;
	case CALLBACK_GET_ITEM_INFO:
		callback_get_item_info (cb, res, NULL);
		break;
	case CALLBACK_GET_ATTRIBUTES:
		callback_get_attributes (cb, res, NULL);
		break;
	default:
		g_assert_not_reached ();
	}
}

void
callback_clear (Callback *cb)
{
	g_assert (cb);
	if (cb->user_data && cb->destroy_func)
		(cb->destroy_func) (cb->user_data);
	cb->user_data = NULL;
	cb->destroy_func = NULL;
	cb->callback = NULL;
}
