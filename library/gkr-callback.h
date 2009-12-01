/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-callback.h - callbacks similar to closures

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

#ifndef GKR_CALLBACK_H
#define GKR_CALLBACK_H

#include <dbus/dbus.h>

typedef struct _GkrOperation GkrOperation;

typedef enum {
	GKR_CALLBACK_OP_MSG = 1,
	GKR_CALLBACK_RES,
	GKR_CALLBACK_RES_STRING,
	GKR_CALLBACK_RES_UINT,
	GKR_CALLBACK_RES_LIST,
	GKR_CALLBACK_RES_KEYRING_INFO,
	GKR_CALLBACK_RES_ITEM_INFO,
	GKR_CALLBACK_RES_ATTRIBUTES
} GkrCallbackType;

typedef struct _GkrCallback {
	GkrCallbackType type;
	gpointer callback;
	gpointer user_data;
	GDestroyNotify destroy_func;
} GkrCallback;

GkrCallback* gkr_callback_new                     (gpointer callback,
                                                   GkrCallbackType callback_type,
                                                   gpointer user_data,
                                                   GDestroyNotify destroy_func);

void         gkr_callback_free                    (gpointer data);

void         gkr_callback_invoke_op_msg           (GkrCallback *cb,
                                                   GkrOperation *op,
                                                   DBusMessage *msg);

void         gkr_callback_invoke_res              (GkrCallback *cb,
                                                   GnomeKeyringResult res);

void         gkr_callback_invoke_res_string       (GkrCallback *cb,
                                                   GnomeKeyringResult res,
                                                   const gchar *value);

void         gkr_callback_invoke_res_uint         (GkrCallback *cb,
                                                   GnomeKeyringResult res,
                                                   guint32 value);

void         gkr_callback_invoke_res_list         (GkrCallback *cb,
                                                   GnomeKeyringResult res,
                                                   GList *value);

void         gkr_callback_invoke_res_keyring_info (GkrCallback *cb,
                                                   GnomeKeyringResult res,
                                                   GnomeKeyringInfo *value);

void         gkr_callback_invoke_res_item_info    (GkrCallback *cb,
                                                   GnomeKeyringResult res,
                                                   GnomeKeyringItemInfo *value);

void         gkr_callback_invoke_res_attributes   (GkrCallback *cb,
                                                   GnomeKeyringResult res,
                                                   GnomeKeyringAttributeList *value);

#endif /* GKR_CALLBACK_H */
