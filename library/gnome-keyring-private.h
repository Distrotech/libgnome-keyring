/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-private.h - private header for keyring

   Copyright (C) 2003 Red Hat, Inc

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
*/

#ifndef GNOME_KEYRING_PRIVATE_H
#define GNOME_KEYRING_PRIVATE_H

#include "gnome-keyring.h"

#include <dbus/dbus.h>

struct GnomeKeyringApplicationRef {
	char *display_name;
	char *pathname;
};

struct GnomeKeyringAccessControl {
	GnomeKeyringApplicationRef *application; /* null for all */
	GnomeKeyringAccessType types_allowed;
};

struct GnomeKeyringInfo {
	gboolean lock_on_idle;
	guint32 lock_timeout;
	time_t mtime;
	time_t ctime;
	gboolean is_locked;
};

struct GnomeKeyringItemInfo {
	GnomeKeyringItemType type;
	char *display_name;
	char *secret;
	time_t mtime;
	time_t ctime;
};

void   _gnome_keyring_memory_dump (void);
extern gboolean gnome_keyring_memory_warning;

typedef enum {
	CALLBACK_DONE,
	CALLBACK_GET_STRING,
	CALLBACK_GET_INT,
	CALLBACK_GET_LIST,
	CALLBACK_GET_KEYRING_INFO,
	CALLBACK_GET_ITEM_INFO,
	CALLBACK_GET_ATTRIBUTES
} CallbackType;

typedef struct _Callback {
	CallbackType type;
	gpointer callback;
	gpointer user_data;
	GDestroyNotify destroy_func;
	gboolean called;
} Callback;

void                callback_done               (Callback *cb,
                                                 GnomeKeyringResult res);

void                callback_get_string         (Callback *cb,
                                                 GnomeKeyringResult res,
                                                 const gchar *string);

void                callback_get_int            (Callback *cb,
                                                 GnomeKeyringResult res,
                                                 guint32 val);

void                callback_get_list           (Callback *cb,
                                                 GnomeKeyringResult res,
                                                 GList *list);

void                callback_get_keyring_info   (Callback *cb,
                                                 GnomeKeyringResult res,
                                                 GnomeKeyringInfo *info);

void                callback_get_item_info      (Callback *cb,
                                                 GnomeKeyringResult res,
                                                 GnomeKeyringItemInfo *info);

void                callback_get_attributes     (Callback *cb,
                                                 GnomeKeyringResult res,
                                                 GnomeKeyringAttributeList *attrs);

void                callback_no_data            (Callback *cb,
                                                 GnomeKeyringResult res);

void                callback_clear              (Callback *cb);

typedef struct _Operation Operation;

typedef void        (*OperationHandler)          (Operation *op,
                                                  Callback *cb,
                                                  DBusMessage *reply,
                                                  gpointer user_data);

Operation*          operation_ref               (gpointer data);

void                operation_unref             (gpointer data);

Operation*          operation_new               (gpointer callback,
                                                 CallbackType callback_type,
                                                 gpointer user_data,
                                                 GDestroyNotify destroy_func);

GnomeKeyringResult  operation_get_result        (Operation *op);

gboolean            operation_set_result        (Operation *op,
                                                 GnomeKeyringResult res);

void                operation_set_handler       (Operation *op,
                                                 OperationHandler handler);

void                operation_set_data          (Operation *op,
                                                 gpointer user_data,
                                                 GDestroyNotify destroy_func);

void                operation_schedule_complete (Operation *op,
                                                 GnomeKeyringResult result);

void                operation_start             (Operation *op,
                                                 DBusMessage *request);

void                operation_prompt            (Operation *op,
                                                 const gchar *prompt);

GnomeKeyringResult  block_request               (DBusMessage *req,
                                                 DBusMessage **reply);

GnomeKeyringResult  block_prompt                (const gchar *prompt,
                                                 DBusMessage **reply);

#define INCOMPLETE                     -1
#define BROKEN                         GNOME_KEYRING_RESULT_IO_ERROR

#define SECRETS_SERVICE                "org.freedesktop.secrets"
#define SERVICE_PATH                   "/org/freedesktop/secrets"
#define COLLECTION_INTERFACE           "org.freedesktop.Secrets.Collection"
#define ITEM_INTERFACE                 "org.freedesktop.Secrets.Item"
#define PROMPT_INTERFACE               "org.freedesktop.Secrets.Prompt"
#define SERVICE_INTERFACE              "org.freedesktop.Secrets.Service"
#define COLLECTION_PREFIX              "/org/freedesktop/secrets/collection/"
#define COLLECTION_DEFAULT             "/org/freedesktop/secrets/collection/default"

#define NORMAL_ALLOCATOR  ((EggBufferAllocator)g_realloc)
#define SECURE_ALLOCATOR  ((EggBufferAllocator)gnome_keyring_memory_realloc)

#endif /* GNOME_KEYRING_PRIVATE_H */
