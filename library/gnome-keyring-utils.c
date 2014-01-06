/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-utils.c - shared utility functions

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
#include "config.h"

#include <string.h>
#include <glib.h>
#include <glib/gi18n-lib.h>

#include "gnome-keyring.h"
#include "gnome-keyring-private.h"
#include "gnome-keyring-memory.h"

#include "egg/egg-secure-memory.h"

EGG_SECURE_DECLARE (libgnome_keyring_utils);

/**
 * SECTION:gnome-keyring-result
 * @title: Result Codes
 * @short_description: Gnome Keyring Result Codes
 *
 * <warning>All of these APIs are deprecated. Use
 * <ulink href="http://developer.gnome.org/libsecret/stable/">libsecret</ulink>
 * instead.</warning>
 *
 * <para>
 * Result codes used through out GNOME Keyring. Additional result codes may be
 * added from time to time and these should be handled gracefully.
 * </para>
 **/

/**
 * gnome_keyring_free_password:
 * @password: the password to be freed
 *
 * Clears the memory used by password by filling with '\0' and frees the memory
 * after doing this. You should use this function instead of g_free() for
 * secret information.
 *
 * Deprecated: Use secret_password_free() instead.
 **/

/**
 * GnomeKeyringAccessControl:
 *
 * A structure which contains access control information.
 */

/**
 * GnomeKeyringItemType:
 * @GNOME_KEYRING_ITEM_GENERIC_SECRET: Generic secret
 * @GNOME_KEYRING_ITEM_NETWORK_PASSWORD: Network password
 * @GNOME_KEYRING_ITEM_NOTE: Note
 * @GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD: Keyring password
 * @GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD: Password for encryption key
 * @GNOME_KEYRING_ITEM_PK_STORAGE: Key storage password
 * @GNOME_KEYRING_ITEM_LAST_TYPE: Not used
 *
 * The types of items.
 *
 * Deprecated: Use #SecretSchema instead.
 */

/**
 * GnomeKeyringResult:
 * @GNOME_KEYRING_RESULT_OK: The operation completed successfully.
 * @GNOME_KEYRING_RESULT_DENIED: Either the user or daemon denied access.
 * @GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON: Keyring daemon is not available.
 * @GNOME_KEYRING_RESULT_ALREADY_UNLOCKED: Keyring was already unlocked.
 * @GNOME_KEYRING_RESULT_NO_SUCH_KEYRING: No such keyring exists.
 * @GNOME_KEYRING_RESULT_BAD_ARGUMENTS: Bad arguments to function.
 * @GNOME_KEYRING_RESULT_IO_ERROR: Problem communicating with daemon.
 * @GNOME_KEYRING_RESULT_CANCELLED: Operation was cancelled.
 * @GNOME_KEYRING_RESULT_KEYRING_ALREADY_EXISTS: The keyring already exists.
 * @GNOME_KEYRING_RESULT_NO_MATCH: No such match found.
 *
 * Various result codes returned by functions.
 *
 * Deprecated: Errors are returned from libsecret functions as #GError.
 */

/**
 * GnomeKeyringAttribute:
 * @name: The name of the attribute.
 * @type: The data type.
 *
 * An item attribute. Set <code>string</code> if data type is
 * %GNOME_KEYRING_ATTRIBUTE_TYPE_STRING or <code>integer</code> if data type is
 * %GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32
 *
 * Deprecated: libsecret only supports string attributes.
 */

/**
 * GnomeKeyringAccessType:
 * @GNOME_KEYRING_ACCESS_READ: Read access
 * @GNOME_KEYRING_ACCESS_WRITE: Write access
 * @GNOME_KEYRING_ACCESS_REMOVE: Delete access
 *
 * Type of access.
 *
 * Deprecated: libsecret only supports string attributes.
 */

/**
 * GnomeKeyringAccessRestriction:
 * @GNOME_KEYRING_ACCESS_ASK: Ask permission.
 * @GNOME_KEYRING_ACCESS_DENY: Deny permission.
 * @GNOME_KEYRING_ACCESS_ALLOW: Give permission.
 *
 * Type of access restriction.
 *
 * Deprecated: No permission prompts are supported.
 */

/**
 * GnomeKeyringNetworkPasswordData:
 * @keyring: Keyring item stored in.
 * @item_id: The identifier of the item.
 * @protocol: Network protocol or scheme.
 * @server: Server or host name.
 * @object: Share or other object on server.
 * @authtype: Type of authentication.
 * @port: TCP port.
 * @user: User name.
 * @domain: User domain
 * @password: The password.
 *
 * Network password info.
 *
 * Deprecated: Use #SECRET_SCHEMA_COMPAT_NETWORK instead.
 */

void
gnome_keyring_free_password (gchar *password)
{
	egg_secure_strfree (password);
}

/**
 * gnome_keyring_string_list_free:
 * @strings: (element-type utf8): A %GList of string pointers.
 *
 * Free a list of string pointers.
 *
 * Deprecated: Not needed when using libsecret.
 **/
void
gnome_keyring_string_list_free (GList *strings)
{
	g_list_foreach (strings, (GFunc) g_free, NULL);
	g_list_free (strings);
}

/**
 * gnome_keyring_result_to_message:
 * @res: A #GnomeKeyringResult
 *
 * The #GNOME_KEYRING_RESULT_OK and #GNOME_KEYRING_RESULT_CANCELLED
 * codes will return an empty string.
 *
 * Note that there are some results for which the application will need to
 * take appropriate action rather than just display an error message to
 * the user.
 *
 * Return value: a string suitable for display to the user for a given
 * #GnomeKeyringResult, or an empty string if the message wouldn't make
 * sense to a user.
 *
 * Deprecated: libsecret returns errors as #GError directly. Use the
 *             error message field for a description.
 **/
const gchar*
gnome_keyring_result_to_message (GnomeKeyringResult res)
{
	switch (res) {

	/* If the caller asks for messages for these, they get what they deserve */
	case GNOME_KEYRING_RESULT_OK:
	case GNOME_KEYRING_RESULT_CANCELLED:
		return "";

	/* Valid displayable error messages */
	case GNOME_KEYRING_RESULT_DENIED:
		return _("Access Denied");
	case GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON:
		return _("The gnome-keyring-daemon application is not running.");
	case GNOME_KEYRING_RESULT_IO_ERROR:
		return _("Error communicating with gnome-keyring-daemon");
	case GNOME_KEYRING_RESULT_ALREADY_EXISTS:
		return _("A keyring with that name already exists");
	case GNOME_KEYRING_RESULT_BAD_ARGUMENTS:
		return _("Programmer error: The application sent invalid data.");
	case GNOME_KEYRING_RESULT_NO_MATCH:
		return _("No matching results");
	case GNOME_KEYRING_RESULT_NO_SUCH_KEYRING:
		return _("A keyring with that name does not exist.");

	/*
	 * This would be a dumb message to display to the user, we never return
	 * this from the daemon, only here for compatibility
	 */
	case GNOME_KEYRING_RESULT_ALREADY_UNLOCKED:
		return _("The keyring has already been unlocked.");

	default:
		g_return_val_if_reached (NULL);
	};
}

/**
 * gnome_keyring_found_free:
 * @found: a #GnomeKeyringFound
 *
 * Free the memory used by a #GnomeKeyringFound item.
 *
 * You usually want to use gnome_keyring_found_list_free() on the list of
 * results.
 *
 * Deprecated: Deprecated: Not needed when using libsecret.
 */
void
gnome_keyring_found_free (GnomeKeyringFound *found)
{
	if (found == NULL)
		return;
	g_free (found->keyring);
	gnome_keyring_free_password (found->secret);
	gnome_keyring_attribute_list_free (found->attributes);
	g_free (found);
}

/**
 * gnome_keyring_found_copy:
 * @found: a #GnomeKeyringFound
 *
 * Copy a #GnomeKeyringFound item.
 *
 * Return value: (transfer full): The new #GnomeKeyringFound
 *
 * Deprecated: Not needed when using libsecret.
 */
GnomeKeyringFound*
gnome_keyring_found_copy (GnomeKeyringFound *found)
{
	GnomeKeyringFound *copy;

	if (found == NULL)
		return NULL;

	copy = g_new (GnomeKeyringFound, 1);
	copy->keyring = g_strdup (found->keyring);
	copy->item_id = found->item_id;
	copy->attributes = gnome_keyring_attribute_list_copy (found->attributes);
	copy->secret = egg_secure_strdup (found->secret);

	return copy;
}

G_DEFINE_BOXED_TYPE (GnomeKeyringFound,
	gnome_keyring_found,
	gnome_keyring_found_copy,
	gnome_keyring_found_free);

/**
 * gnome_keyring_found_list_free:
 * @found_list: (element-type GnomeKeyringFound): a #GList of #GnomeKeyringFound
 *
 * Free the memory used by the #GnomeKeyringFound items in @found_list.
 *
 * Deprecated: Not needed when using libsecret.
 **/
void
gnome_keyring_found_list_free (GList *found_list)
{
	g_list_foreach (found_list, (GFunc) gnome_keyring_found_free, NULL);
	g_list_free (found_list);
}

/**
 * SECTION:gnome-keyring-attributes
 * @title: Item Attributes
 * @short_description: Attributes of individual keyring items.
 *
 * <warning>All of these APIs are deprecated. Use
 * <ulink href="http://developer.gnome.org/libsecret/stable/">libsecret</ulink>
 * instead.</warning>
 *
 * Attributes allow various other pieces of information to be associated with an item.
 * These can also be used to search for relevant items. Use gnome_keyring_item_get_attributes()
 * or gnome_keyring_item_set_attributes().
 *
 * Attributes are not stored in a secret or encrypted manner by gnome-keyring. Do
 * not store sensitive information in attributes.
 *
 * Each attribute has either a string, or unsigned integer value.
 **/

/**
 * gnome_keyring_attribute_get_string:
 * @attribute: a #GnomeKeyringAttribute
 *
 * Return the string value. It is an error to call this method if
 * @attribute.type is not #GNOME_KEYRING_ATTRIBUTE_TYPE_STRING. This method is
 * mostly useful for language bindings which do not provide union access. In C
 * you should just use attribute->value.string.
 *
 * Returns: (transfer none): The value.string pointer of @attribute. This is
 * not a copy, do not free.
 *
 * Deprecated: Not needed when using libsecret.
 **/
const gchar*
gnome_keyring_attribute_get_string (GnomeKeyringAttribute *attribute)
{
	g_return_val_if_fail (attribute->type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING, NULL);
	return attribute->value.string;
}

/**
 * gnome_keyring_attribute_get_uint32:
 * @attribute: a #GnomeKeyringAttribute
 *
 * Return the uint32 value. It is an error to call this method if
 * @attribute.type is not #GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32. This method is
 * mostly useful for language bindings which do not provide union access. In C
 * you should just use attribute->value.integer.
 *
 * Returns: The value.integer of @attribute.
 *
 * Deprecated: Not needed when using libsecret.
 **/
guint32
gnome_keyring_attribute_get_uint32 (GnomeKeyringAttribute *attribute)
{
	g_return_val_if_fail (attribute->type == GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32, 0);
	return attribute->value.integer;
}

/**
 * gnome_keyring_attribute_free:
 * @attribute: a #GnomeKeyringAttribute.
 *
 * Free the memory used by the #GnomeKeyringAttribute @attribute.
 *
 * Deprecated: Not needed when using libsecret.
 **/
static void
gnome_keyring_attribute_free (GnomeKeyringAttribute *attribute)
{
	if (attribute == NULL)
		return;

	g_free (attribute->name);
	if (attribute->type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
		g_free (attribute->value.string);
	}
	g_free (attribute);
}

/**
 * gnome_keyring_attribute_copy:
 * @attribute: a #GnomeKeyringAttribute to copy.
 *
 * Copy a #GnomeKeyringAttribute.
 *
 * Return value: (transfer full): The new #GnomeKeyringAttribute
 *
 * Deprecated: Not needed when using libsecret.
 **/
static GnomeKeyringAttribute*
gnome_keyring_attribute_copy (GnomeKeyringAttribute *attribute)
{
	GnomeKeyringAttribute *copy;

	if (attribute == NULL)
		return NULL;

	copy = g_new (GnomeKeyringAttribute, 1);
	copy->name = g_strdup (attribute->name);
	copy->type = attribute->type;
	if (attribute->type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
		copy->value.string = g_strdup (attribute->value.string);
	} else {
		copy->value.integer = attribute->value.integer;
	}

	return copy;
}

G_DEFINE_BOXED_TYPE (GnomeKeyringAttribute,
	gnome_keyring_attribute,
	gnome_keyring_attribute_copy,
	gnome_keyring_attribute_free);


/**
 * gnome_keyring_attribute_list_append_string:
 * @attributes: A #GnomeKeyringAttributeList
 * @name: The name of the new attribute
 * @value: The value to store in @attributes
 *
 * Store a key-value-pair with a string value in @attributes.
 *
 * Deprecated: libsecret stores attributes as a #GHashTable containing
 *             string keys and values, use g_hash_table_replace() instead.
 **/
void
gnome_keyring_attribute_list_append_string (GnomeKeyringAttributeList *attributes,
                                            const char *name, const char *value)
{
	GnomeKeyringAttribute attribute;

	g_return_if_fail (attributes);
	g_return_if_fail (name);

	attribute.name = g_strdup (name);
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
	attribute.value.string = g_strdup (value);

	g_array_append_val (attributes, attribute);
}

/**
 * gnome_keyring_attribute_list_append_uint32:
 * @attributes: A #GnomeKeyringAttributeList
 * @name: The name of the new attribute
 * @value: The value to store in @attributes
 *
 * Store a key-value-pair with an unsigned 32bit number value in @attributes.
 *
 * Deprecated: libsecret does not support number attributes.
 **/
void
gnome_keyring_attribute_list_append_uint32 (GnomeKeyringAttributeList *attributes,
                                            const char *name, guint32 value)
{
	GnomeKeyringAttribute attribute;

	g_return_if_fail (attributes);
	g_return_if_fail (name);

	attribute.name = g_strdup (name);
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32;
	attribute.value.integer = value;
	g_array_append_val (attributes, attribute);
}

/**
 * gnome_keyring_attribute_list_new:
 *
 * Create a new #GnomeKeyringAttributeList.
 *
 * Return value: (transfer full): The new #GnomeKeyringAttributeList
 *
 * Deprecated: libsecret stores attributes as a #GHashTable containing
 *             string keys and values; use g_hash_table_new() instead.
 **/
GnomeKeyringAttributeList *
gnome_keyring_attribute_list_new (void)
{
	return g_array_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute));
}

/**
 * gnome_keyring_attribute_list_free:
 * @attributes: A #GnomeKeyringAttributeList
 *
 * Free the memory used by @attributes.
 *
 * If a %NULL pointer is passed, it is ignored.
 *
 * Deprecated: libsecret stores attributes as a #GHashTable containing
 *             string keys and values, use g_hash_table_unref() instead.
 **/
void
gnome_keyring_attribute_list_free (GnomeKeyringAttributeList *attributes)
{
	GnomeKeyringAttribute *array;
	int i;

	if (attributes == NULL)
		return;

	array = (GnomeKeyringAttribute *)attributes->data;
	for (i = 0; i < attributes->len; i++) {
		g_free (array[i].name);
		if (array[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
			g_free (array[i].value.string);
		}
	}

	g_array_free (attributes, TRUE);
}

/**
 * gnome_keyring_attribute_list_copy:
 * @attributes: A #GnomeKeyringAttributeList to copy.
 *
 * Copy a list of item attributes.
 *
 * Return value: (transfer full): The new #GnomeKeyringAttributeList
 *
 * Deprecated: Not needed when using libsecret.
 **/
GnomeKeyringAttributeList *
gnome_keyring_attribute_list_copy (GnomeKeyringAttributeList *attributes)
{
	GnomeKeyringAttribute *array;
	GnomeKeyringAttributeList *copy;
	int i;

	if (attributes == NULL)
		return NULL;

	copy = g_array_sized_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute), attributes->len);

	copy->len = attributes->len;
	memcpy (copy->data, attributes->data, sizeof (GnomeKeyringAttribute) * attributes->len);

	array = (GnomeKeyringAttribute *)copy->data;
	for (i = 0; i < copy->len; i++) {
		array[i].name = g_strdup (array[i].name);
		if (array[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
			array[i].value.string = g_strdup (array[i].value.string);
		}
	}
	return copy;
}

/**
 * gnome_keyring_attribute_list_to_glist:
 * @attributes: A #GnomeKeyringAttributeList
 *
 * Create #GList of #GnomeKeyringAttribute pointers from @attributes. This is
 * mostly useful in language bindings which cannot directly use a #GArray.
 *
 * Returns: (transfer full) (element-type GnomeKeyringAttribute): #GList
 * of #GnomeKeyringAttribute.
 *
 * Since: 3.4
 *
 * Deprecated: Not needed when using libsecret.
 **/
GList*
gnome_keyring_attribute_list_to_glist (GnomeKeyringAttributeList *attributes)
{
	GList *list = NULL;
	GnomeKeyringAttribute *attr;
	guint i;

	if (attributes == NULL)
		return NULL;

	for (i = 0; i < attributes->len; ++i) {
		attr = &g_array_index (attributes, GnomeKeyringAttribute, i);
		list = g_list_append (list, gnome_keyring_attribute_copy (attr));
	}

	return list;
}

G_DEFINE_BOXED_TYPE (GnomeKeyringAttributeList,
	gnome_keyring_attribute_list,
	gnome_keyring_attribute_list_copy,
	gnome_keyring_attribute_list_free);

/**
 * SECTION:gnome-keyring-keyring-info
 * @title: Keyring Info
 * @short_description: Keyring Information
 *
 * <warning>All of these APIs are deprecated. Use
 * <ulink href="http://developer.gnome.org/libsecret/stable/">libsecret</ulink>
 * instead.</warning>
 *
 * Use gnome_keyring_get_info() or gnome_keyring_get_info_sync() to get a #GnomeKeyringInfo
 * pointer to use with these functions.
 **/

/**
 * gnome_keyring_info_free:
 * @keyring_info: The keyring info to free.
 *
 * Free a #GnomeKeyringInfo object. If a %NULL pointer is passed
 * nothing occurs.
 *
 * Deprecated: Use #SecretCollection objects instead.
 **/
void
gnome_keyring_info_free (GnomeKeyringInfo *keyring_info)
{
	g_free (keyring_info);
}

/**
 * SECTION:gnome-keyring-item-info
 * @title: Item Information
 * @short_description: Keyring Item Info
 *
 * <warning>All of these APIs are deprecated. Use
 * <ulink href="http://developer.gnome.org/libsecret/stable/">libsecret</ulink>
 * instead.</warning>
 *
 * #GnomeKeyringItemInfo represents the basic information about a keyring item.
 * Use gnome_keyring_item_get_info() or gnome_keyring_item_set_info().
 **/

/**
 * gnome_keyring_info_copy:
 * @keyring_info: The keyring info to copy.
 *
 * Copy a #GnomeKeyringInfo object.
 *
 * Return value: The newly allocated #GnomeKeyringInfo. This must be freed with
 * gnome_keyring_info_free()
 *
 * Deprecated: Use #SecretCollection objects instead.
 **/
GnomeKeyringInfo *
gnome_keyring_info_copy (GnomeKeyringInfo *keyring_info)
{
	GnomeKeyringInfo *copy;

	if (keyring_info == NULL)
		return NULL;

	copy = g_new (GnomeKeyringInfo, 1);
	memcpy (copy, keyring_info, sizeof (GnomeKeyringInfo));

	return copy;
}

G_DEFINE_BOXED_TYPE (GnomeKeyringInfo,
	gnome_keyring_info,
	gnome_keyring_info_copy,
	gnome_keyring_info_free);

/**
 * gnome_keyring_item_info_free:
 * @item_info: The keyring item info pointer.
 *
 * Free the #GnomeKeyringItemInfo object.
 *
 * A %NULL pointer may be passed, in which case it will be ignored.
 *
 * Deprecated: Use #SecretItem objects instead.
 **/
void
gnome_keyring_item_info_free (GnomeKeyringItemInfo *item_info)
{
	if (item_info != NULL) {
		g_free (item_info->display_name);
		gnome_keyring_free_password (item_info->secret);
		g_free (item_info);
	}
}

/**
 * gnome_keyring_item_info_new:
 *
 * Create a new #GnomeKeyringItemInfo object.
 * Free the #GnomeKeyringItemInfo object.
 *
 * Return value: A keyring item info pointer.
 *
 * Deprecated: Use #SecretItem objects instead.
 **/
GnomeKeyringItemInfo *
gnome_keyring_item_info_new (void)
{
	GnomeKeyringItemInfo *info;

	info = g_new0 (GnomeKeyringItemInfo, 1);

	info->type = GNOME_KEYRING_ITEM_NO_TYPE;

	return info;
}

/**
 * gnome_keyring_item_info_copy:
 * @item_info: A keyring item info pointer.
 *
 * Copy a #GnomeKeyringItemInfo object.
 *
 * Return value: A keyring item info pointer.
 *
 * Deprecated: Use #SecretItem objects instead.
 **/
GnomeKeyringItemInfo *
gnome_keyring_item_info_copy (GnomeKeyringItemInfo *item_info)
{
	GnomeKeyringItemInfo *copy;

	if (item_info == NULL)
		return NULL;

	copy = g_new (GnomeKeyringItemInfo, 1);
	memcpy (copy, item_info, sizeof (GnomeKeyringItemInfo));

	copy->display_name = g_strdup (item_info->display_name);
	copy->secret = egg_secure_strdup (item_info->secret);

	return copy;
}

/* gnome_keyring_item_info_get_type() is already part of the API, cannot use
 * G_DEFINE_BOXED_TYPE here */
GType
gnome_keyring_item_info_get_gtype (void)
{
    static volatile gsize initialized = 0;
    static GType type = 0;

    if (g_once_init_enter (&initialized)) {
	type = g_boxed_type_register_static ("GnomeKeyringItemInfo",
	    (GBoxedCopyFunc) gnome_keyring_item_info_copy,
	    (GBoxedFreeFunc) gnome_keyring_item_info_free);
	g_once_init_leave (&initialized, 1);
    }

    return type;
}

/**
 * gnome_keyring_application_ref_new:
 *
 * Create a new application reference.
 *
 * Return value: A new #GnomeKeyringApplicationRef pointer.
 *
 * Deprecated: Not needed when using libsecret.
 **/
GnomeKeyringApplicationRef *
gnome_keyring_application_ref_new (void)
{
	GnomeKeyringApplicationRef *app_ref;

	app_ref = g_new0 (GnomeKeyringApplicationRef, 1);

	return app_ref;
}

/**
 * gnome_keyring_application_ref_free:
 * @app: A #GnomeKeyringApplicationRef pointer
 *
 * Free an application reference.
 *
 * Deprecated: Not needed when using libsecret.
 **/
void
gnome_keyring_application_ref_free (GnomeKeyringApplicationRef *app)
{
	if (app) {
		g_free (app->display_name);
		g_free (app->pathname);
		g_free (app);
	}
}

/**
 * gnome_keyring_application_ref_copy:
 * @app: A #GnomeKeyringApplicationRef pointer
 *
 * Copy an application reference.
 *
 * Return value: A new #GnomeKeyringApplicationRef pointer.
 *
 * Deprecated: Not needed when using libsecret.
 **/
GnomeKeyringApplicationRef *
gnome_keyring_application_ref_copy (const GnomeKeyringApplicationRef *app)
{
	GnomeKeyringApplicationRef *copy;

	if (app == NULL)
		return NULL;

	copy = g_new (GnomeKeyringApplicationRef, 1);
	copy->display_name = g_strdup (app->display_name);
	copy->pathname = g_strdup (app->pathname);

	return copy;
}

G_DEFINE_BOXED_TYPE (GnomeKeyringApplicationRef,
	gnome_keyring_application_ref,
	gnome_keyring_application_ref_copy,
	gnome_keyring_application_ref_free);

/**
 * gnome_keyring_access_control_new:
 * @application: A #GnomeKeyringApplicationRef pointer
 * @types_allowed: Access types allowed.
 *
 * Create a new access control for an item. Combine the various access
 * rights allowed.
 *
 * Return value: The new #GnomeKeyringAccessControl pointer. Use
 * gnome_keyring_access_control_free() to free the memory.
 *
 * Deprecated: Not needed when using libsecret.
 **/
GnomeKeyringAccessControl *
gnome_keyring_access_control_new (const GnomeKeyringApplicationRef *application,
                                  GnomeKeyringAccessType types_allowed)
{
	GnomeKeyringAccessControl *ac;
	ac = g_new (GnomeKeyringAccessControl, 1);

	ac->application = gnome_keyring_application_ref_copy (application);
	ac->types_allowed = types_allowed;

	return ac;
}

/**
 * gnome_keyring_access_control_free:
 * @ac: A #GnomeKeyringAccessControl pointer
 *
 * Free an access control for an item.
 *
 * Deprecated: Not needed when using libsecret.
 **/
void
gnome_keyring_access_control_free (GnomeKeyringAccessControl *ac)
{
	if (ac == NULL)
		return;
	gnome_keyring_application_ref_free (ac->application);
	g_free (ac);
}

/**
 * gnome_keyring_access_control_copy:
 * @ac: A #GnomeKeyringAccessControl pointer
 *
 * Copy an access control for an item.
 *
 * Return value: The new #GnomeKeyringAccessControl pointer. Use
 * gnome_keyring_access_control_free() to free the memory.
 *
 * Deprecated: Not needed when using libsecret.
 **/
GnomeKeyringAccessControl *
gnome_keyring_access_control_copy (GnomeKeyringAccessControl *ac)
{
	GnomeKeyringAccessControl *ret;

	if (ac == NULL)
		return NULL;

	ret = gnome_keyring_access_control_new (gnome_keyring_application_ref_copy (ac->application), ac->types_allowed);

	return ret;
}

G_DEFINE_BOXED_TYPE (GnomeKeyringAccessControl,
	gnome_keyring_access_control,
	gnome_keyring_access_control_copy,
	gnome_keyring_access_control_free);

/**
 * gnome_keyring_acl_copy:
 * @list: (element-type GnomeKeyringAccessControl): A list of
 *        #GnomeKeyringAccessControl pointers.
 *
 * Copy an access control list.
 *
 * Return value: (transfer full) (element-type GnomeKeyringAccessControl):
 * A new list of #GnomeKeyringAccessControl items. Use gnome_keyring_acl_free()
 * to free the memory.
 *
 * Deprecated: Not needed when using libsecret.
 **/
GList *
gnome_keyring_acl_copy (GList *list)
{
	GList *ret, *l;

	ret = g_list_copy (list);
	for (l = ret; l != NULL; l = l->next) {
		l->data = gnome_keyring_access_control_copy (l->data);
	}

	return ret;
}

/**
 * gnome_keyring_acl_free:
 * @acl: (element-type GnomeKeyringAccessControl): A list of
 *       #GnomeKeyringAccessControl pointers.
 *
 * Free an access control list.
 *
 * Deprecated: Not needed when using libsecret.
 **/
void
gnome_keyring_acl_free (GList *acl)
{
	g_list_foreach (acl, (GFunc)gnome_keyring_access_control_free, NULL);
	g_list_free (acl);
}

/**
 * gnome_keyring_info_set_lock_on_idle:
 * @keyring_info: The keyring info.
 * @value: Whether to lock or not.
 *
 * Set whether or not to lock a keyring after a certain amount of idle time.
 *
 * See also gnome_keyring_info_set_lock_timeout().
 *
 * Deprecated: Not supported when using libsecret.
 **/
void
gnome_keyring_info_set_lock_on_idle (GnomeKeyringInfo *keyring_info,
                                     gboolean          value)
{
	g_return_if_fail (keyring_info);
	keyring_info->lock_on_idle = value;
}

/**
 * gnome_keyring_info_get_lock_on_idle:
 * @keyring_info: The keyring info.
 *
 * Get whether or not to lock a keyring after a certain amount of idle time.
 *
 * See also gnome_keyring_info_get_lock_timeout().
 *
 * Return value: Whether to lock or not.
 *
 * Deprecated: Not supported when using libsecret.
 **/
gboolean
gnome_keyring_info_get_lock_on_idle (GnomeKeyringInfo *keyring_info)
{
	g_return_val_if_fail (keyring_info, FALSE);
	return keyring_info->lock_on_idle;
}

/**
 * gnome_keyring_info_set_lock_timeout:
 * @keyring_info: The keyring info.
 * @value: The lock timeout in seconds.
 *
 * Set the idle timeout, in seconds, after which to lock the keyring.
 *
 * See also gnome_keyring_info_set_lock_on_idle().
 *
 * Deprecated: Not supported when using libsecret.
 **/
void
gnome_keyring_info_set_lock_timeout (GnomeKeyringInfo *keyring_info,
                                     guint32           value)
{
	g_return_if_fail (keyring_info);
	keyring_info->lock_timeout = value;
}

/**
 * gnome_keyring_info_get_lock_timeout:
 * @keyring_info: The keyring info.
 *
 * Get the idle timeout, in seconds, after which to lock the keyring.
 *
 * See also gnome_keyring_info_get_lock_on_idle().
 *
 * Return value: The idle timeout, in seconds.
 *
 * Deprecated: Not supported when using libsecret.
 **/
guint32
gnome_keyring_info_get_lock_timeout (GnomeKeyringInfo *keyring_info)
{
	g_return_val_if_fail (keyring_info, 0);
	return keyring_info->lock_timeout;
}

/**
 * gnome_keyring_info_get_mtime:
 * @keyring_info: The keyring info.
 *
 * Get the time at which the keyring was last modified.
 *
 * Return value: The last modified time.
 *
 * Deprecated: Use secret_collection_get_modified() instead.
 **/
time_t
gnome_keyring_info_get_mtime (GnomeKeyringInfo *keyring_info)
{
	g_return_val_if_fail (keyring_info, 0);
	return keyring_info->mtime;
}

/**
 * gnome_keyring_info_get_ctime:
 * @keyring_info: The keyring info.
 *
 * Get the time at which the keyring was created.
 *
 * Return value: The created time.
 *
 * Deprecated: Use secret_collection_get_created() instead.
 **/
time_t
gnome_keyring_info_get_ctime (GnomeKeyringInfo *keyring_info)
{
	g_return_val_if_fail (keyring_info, 0);
	return keyring_info->ctime;
}

/**
 * gnome_keyring_info_get_is_locked:
 * @keyring_info: The keyring info.
 *
 * Get whether the keyring is locked or not.
 *
 * Return value: Whether the keyring is locked or not.
 *
 * Deprecated: Use secret_collection_get_locked() instead.
 **/
gboolean
gnome_keyring_info_get_is_locked (GnomeKeyringInfo *keyring_info)
{
	g_return_val_if_fail (keyring_info, FALSE);
	return keyring_info->is_locked;
}

/**
 * gnome_keyring_item_info_get_type:
 * @item_info: A keyring item info pointer.
 *
 * Get the item type.
 *
 * Return value: The item type
 *
 * Deprecated: Use secret_item_get_schema_name() instead.
 **/
GnomeKeyringItemType
gnome_keyring_item_info_get_type (GnomeKeyringItemInfo *item_info)
{
	g_return_val_if_fail (item_info, 0);
	return item_info->type;
}

/**
 * gnome_keyring_item_info_set_type:
 * @item_info: A keyring item info pointer.
 * @type: The new item type
 *
 * Set the type on an item info.
 *
 * Deprecated: Use secret_item_set_attributes() instead.
 **/
void
gnome_keyring_item_info_set_type (GnomeKeyringItemInfo *item_info,
                                  GnomeKeyringItemType  type)
{
	g_return_if_fail (item_info);
	item_info->type = type;
}

/**
 * gnome_keyring_item_info_get_secret:
 * @item_info: A keyring item info pointer.
 *
 * Get the item secret.
 *
 * Return value: The newly allocated string containing the item secret.
 *
 * Deprecated: Use secret_item_get_secret() instead.
 **/
char *
gnome_keyring_item_info_get_secret (GnomeKeyringItemInfo *item_info)
{
	/* XXXX For compatibility reasons we can't use secure memory here */
	g_return_val_if_fail (item_info, NULL);
	return g_strdup (item_info->secret);
}

/**
 * gnome_keyring_item_info_set_secret:
 * @item_info: A keyring item info pointer.
 * @value: The new item secret
 *
 * Set the secret on an item info.
 *
 * Deprecated: Use secret_item_set_secret() instead.
 **/
void
gnome_keyring_item_info_set_secret (GnomeKeyringItemInfo *item_info,
                                    const char           *value)
{
	g_return_if_fail (item_info);
	gnome_keyring_free_password (item_info->secret);
	item_info->secret = gnome_keyring_memory_strdup (value);
}

/**
 * gnome_keyring_item_info_get_display_name:
 * @item_info: A keyring item info pointer.
 *
 * Get the item display name.
 *
 * Return value: The newly allocated string containing the item display name.
 *
 * Deprecated: Use secret_item_get_label() instead.
 **/
char *
gnome_keyring_item_info_get_display_name (GnomeKeyringItemInfo *item_info)
{
	g_return_val_if_fail (item_info, NULL);
	return g_strdup (item_info->display_name);
}

/**
 * gnome_keyring_item_info_set_display_name:
 * @item_info: A keyring item info pointer.
 * @value: The new display name.
 *
 * Set the display name on an item info.
 *
 * Deprecated: Use secret_item_set_label() instead.
 **/
void
gnome_keyring_item_info_set_display_name (GnomeKeyringItemInfo *item_info,
                                          const char           *value)
{
	g_return_if_fail (item_info);
	g_free (item_info->display_name);
	item_info->display_name = g_strdup (value);
}

/**
 * gnome_keyring_item_info_get_mtime:
 * @item_info: A keyring item info pointer.
 *
 * Get the item last modified time.
 *
 * Return value: The item last modified time.
 *
 * Deprecated: Use secret_item_get_modified() instead.
 **/
time_t
gnome_keyring_item_info_get_mtime (GnomeKeyringItemInfo *item_info)
{
	g_return_val_if_fail (item_info, 0);
	return item_info->mtime;
}

/**
 * gnome_keyring_item_info_get_ctime:
 * @item_info: A keyring item info pointer.
 *
 * Get the item created time.
 *
 * Return value: The item created time.
 *
 * Deprecated: Use secret_item_get_created() instead.
 **/
time_t
gnome_keyring_item_info_get_ctime (GnomeKeyringItemInfo *item_info)
{
	g_return_val_if_fail (item_info, 0);
	return item_info->ctime;
}

/**
 * SECTION:gnome-keyring-acl
 * @title: Item ACLs
 * @short_description: Access control lists for keyring items.
 *
 * <warning>All of these APIs are deprecated. Use
 * <ulink href="http://developer.gnome.org/libsecret/stable/">libsecret</ulink>
 * instead.</warning>
 *
 * Each item has an access control list, which specifies the applications that
 * can read, write or delete an item. The read access applies only to reading the secret.
 * All applications can read other parts of the item. ACLs are accessed and changed
 * gnome_keyring_item_get_acl() and gnome_keyring_item_set_acl().
 **/

/**
 * gnome_keyring_item_ac_get_display_name:
 * @ac: A #GnomeKeyringAccessControl pointer.
 *
 * Get the access control application's display name.
 *
 * Return value: A newly allocated string containing the display name.
 *
 * Deprecated: Not supported when using libsecret.
 **/
char *
gnome_keyring_item_ac_get_display_name (GnomeKeyringAccessControl *ac)
{
	g_return_val_if_fail (ac, NULL);
	return g_strdup (ac->application->display_name);
}

/**
 * gnome_keyring_item_ac_set_display_name:
 * @ac: A #GnomeKeyringAccessControl pointer.
 * @value: The new application display name.
 *
 * Set the access control application's display name.
 *
 * Deprecated: Not supported when using libsecret.
 **/
void
gnome_keyring_item_ac_set_display_name (GnomeKeyringAccessControl *ac,
                                        const char                *value)
{
	g_return_if_fail (ac);
	g_free (ac->application->display_name);
	ac->application->display_name = g_strdup (value);
}

/**
 * gnome_keyring_item_ac_get_path_name:
 * @ac: A #GnomeKeyringAccessControl pointer.
 *
 * Get the access control application's full path name.
 *
 * Return value: A newly allocated string containing the display name.
 *
 * Deprecated: Not supported when using libsecret.
 **/
char *
gnome_keyring_item_ac_get_path_name (GnomeKeyringAccessControl *ac)
{
	g_return_val_if_fail (ac, NULL);
	return g_strdup (ac->application->pathname);
}

/**
 * gnome_keyring_item_ac_set_path_name:
 * @ac: A #GnomeKeyringAccessControl pointer
 * @value: The new application full path.
 *
 * Set the access control application's full path name.
 *
 * Deprecated: Not supported when using libsecret.
 **/
void
gnome_keyring_item_ac_set_path_name (GnomeKeyringAccessControl *ac,
                                     const char                *value)
{
	g_return_if_fail (ac);
	g_free (ac->application->pathname);
	ac->application->pathname = g_strdup (value);
}

/**
 * gnome_keyring_item_ac_get_access_type:
 * @ac: A #GnomeKeyringAccessControl pointer.
 *
 * Get the application access rights for the access control.
 *
 * Return value: The access rights.
 *
 * Deprecated: Not supported when using libsecret.
 **/
GnomeKeyringAccessType
gnome_keyring_item_ac_get_access_type (GnomeKeyringAccessControl *ac)
{
	g_return_val_if_fail (ac, 0);
	return ac->types_allowed;
}

/**
 * gnome_keyring_item_ac_set_access_type:
 * @ac: A #GnomeKeyringAccessControl pointer.
 * @value: The new access rights.
 *
 * Set the application access rights for the access control.
 *
 * Deprecated: Not supported when using libsecret.
 **/
void
gnome_keyring_item_ac_set_access_type (GnomeKeyringAccessControl *ac,
                                       const GnomeKeyringAccessType value)
{
	g_return_if_fail (ac);
	ac->types_allowed = value;
}
