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

#ifndef GKR_OPERATION_H
#define GKR_OPERATION_H

#include "gkr-callback.h"

#include <dbus/dbus.h>

GkrOperation*       gkr_operation_ref               (GkrOperation *op);

void                gkr_operation_unref             (gpointer data);

GkrOperation*       gkr_operation_new               (gpointer callback,
                                                     GkrCallbackType callback_type,
                                                     gpointer user_data,
                                                     GDestroyNotify destroy_func);

GkrCallback*        gkr_operation_push              (GkrOperation *op,
                                                     gpointer callback,
                                                     GkrCallbackType callback_type,
                                                     gpointer user_data,
                                                     GDestroyNotify destroy_func);

GkrCallback*        gkr_operation_pop               (GkrOperation *op);

void                gkr_operation_complete          (GkrOperation *op,
                                                     GnomeKeyringResult res);

void                gkr_operation_complete_later    (GkrOperation *op,
                                                     GnomeKeyringResult res);

void                gkr_operation_request           (GkrOperation *op,
                                                     DBusMessage *request);

gboolean            gkr_operation_handle_errors     (GkrOperation *op,
                                                     DBusMessage *reply);

void                gkr_operation_prompt            (GkrOperation *op,
                                                     const gchar *prompt);

GnomeKeyringResult  gkr_operation_request_sync      (DBusMessage *request,
                                                     DBusMessage **reply);

GnomeKeyringResult  gkr_operation_prompt_sync       (const gchar *prompt,
                                                     DBusMessage **reply);

#endif /* GKR_OPERATION_H */
