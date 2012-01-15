#!/usr/bin/python3
#
# Test GnomeKeyring GI binding
# Copyright (C) 2012 Martin Pitt <martin.pitt@ubuntu.com>
#
# The Gnome Keyring Library  library is free software; you can redistribute it
# and/or modify it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

import sys
import os
import unittest

# use source tree typelib
os.environ['GI_TYPELIB_PATH'] = 'library:' + os.environ.get('GI_TYPELIB_PATH', '')

from gi.repository import GLib
from gi.repository import GnomeKeyring

# name of test keyring
TEST_KEYRING = '__gnomekeyring_test'
TEST_PWD = 'secret'

class KeyringTest(unittest.TestCase):
    def tearDown(self):
        '''Ensure that we do no leave test keyring behind.'''

        GnomeKeyring.delete_sync(TEST_KEYRING)

    def test_info_default(self):
        '''get_info_sync() for default keyring'''

        # we cannot assume too much about the default keyring; it might be
        # locked or not, and we should avoid poking in it too much
        (result, info) = GnomeKeyring.get_info_sync(None)
        self.assertEqual(result, GnomeKeyring.Result.OK)
        self.assertTrue(info.get_is_locked() in (False, True))

    def test_info_unknown(self):
        '''get_info_sync() for unknown keyring'''

        (result, info) = GnomeKeyring.get_info_sync(TEST_KEYRING + '_nonexisting')
        self.assertEqual(result, GnomeKeyring.Result.NO_SUCH_KEYRING)

    def test_create_lock(self):
        '''create_sync() and locking/unlocking'''

        # create
        self.assertEqual(GnomeKeyring.create_sync(TEST_KEYRING, TEST_PWD),
                GnomeKeyring.Result.OK)
        (result, info) = GnomeKeyring.get_info_sync(TEST_KEYRING)
        self.assertEqual(result, GnomeKeyring.Result.OK)
        self.assertFalse(info.get_is_locked())

        # try to create already existing ring
        self.assertEqual(GnomeKeyring.create_sync(TEST_KEYRING, TEST_PWD),
                GnomeKeyring.Result.KEYRING_ALREADY_EXISTS)

        # lock
        self.assertEqual(GnomeKeyring.lock_sync(TEST_KEYRING),
                GnomeKeyring.Result.OK)
        self.assertTrue(GnomeKeyring.get_info_sync(TEST_KEYRING)[1].get_is_locked())

        # unlock with wrong password
        self.assertEqual(GnomeKeyring.unlock_sync(TEST_KEYRING, 'h4ck'),
                GnomeKeyring.Result.IO_ERROR)

        # unlock with correct password
        self.assertEqual(GnomeKeyring.unlock_sync(TEST_KEYRING, TEST_PWD),
                GnomeKeyring.Result.OK)

    def test_find_items(self):
        '''find_items_sync()'''

        search_attrs = GnomeKeyring.Attribute.list_new()

        # no attributes, finds everything
        (result, items) = GnomeKeyring.find_items_sync(
                GnomeKeyring.ItemType.GENERIC_SECRET,
                search_attrs)
        self.assertEqual(result, GnomeKeyring.Result.OK)
        print('(no attributes: %i matches) ' % len(items), end='', file=sys.stderr)
        for item in items:
            self.assertNotEqual(item.keyring, '')
            for attr in GnomeKeyring.Attribute.list_to_glist(item.attributes):
                self.assertTrue(attr.type in (GnomeKeyring.AttributeType.STRING,
                            GnomeKeyring.AttributeType.UINT32))
                self.assertEqual(type(attr.name), type(''))
                self.assertGreater(len(attr.name), 0)

                # check that we can get the value
                if attr.type == GnomeKeyring.AttributeType.STRING:
                    self.assertEqual(type(attr.get_string()), type(''))
                else:
                    self.assertTrue(isinstance(attr.get_uint32()), long)

        # search for unknown attribute, should have no results
        GnomeKeyring.Attribute.list_append_string(search_attrs, 'unknown!_attr', '')
        (result, items) = GnomeKeyring.find_items_sync(
                GnomeKeyring.ItemType.GENERIC_SECRET,
                search_attrs)
        self.assertEqual(result, GnomeKeyring.Result.NO_MATCH)
        self.assertEqual(len(items), 0)

    def test_item_create_info(self):
        '''item_create_sync(),  item_get_info_sync(), list_item_ids_sync()'''

        self.assertEqual(GnomeKeyring.create_sync(TEST_KEYRING, TEST_PWD),
                GnomeKeyring.Result.OK)
        self.assertEqual(GnomeKeyring.get_info_sync(TEST_KEYRING)[0], GnomeKeyring.Result.OK)

        attrs = GnomeKeyring.Attribute.list_new()
        GnomeKeyring.Attribute.list_append_string(attrs, 'context', 'testsuite')
        GnomeKeyring.Attribute.list_append_uint32(attrs, 'answer', 42)

        (result, id) = GnomeKeyring.item_create_sync(TEST_KEYRING,
                GnomeKeyring.ItemType.GENERIC_SECRET, 'my_password', attrs,
                'my_secret', False)
        self.assertEqual(result, GnomeKeyring.Result.OK)

        # now query for it
        (result, info) = GnomeKeyring.item_get_info_sync(TEST_KEYRING, id)
        self.assertEqual(result, GnomeKeyring.Result.OK)
        self.assertEqual(info.get_display_name(), 'my_password')
        self.assertEqual(info.get_secret(), 'my_secret')

        # list_item_ids_sync()
        (result, items) = GnomeKeyring.list_item_ids_sync(TEST_KEYRING)
        self.assertEqual(result, GnomeKeyring.Result.OK)
        self.assertEqual(items, [id])

    def test_result_str(self):
        '''result_to_message()'''

        self.assertEqual(GnomeKeyring.result_to_message(GnomeKeyring.Result.OK),
                '')
        self.assertEqual(
                type(GnomeKeyring.result_to_message(GnomeKeyring.Result.NO_SUCH_KEYRING)),
                type(''))


#
# main
#

if not GnomeKeyring.is_available():
    print('GNOME keyring not available', file=sys.stderr)
    sys.exit(0)
unittest.main()
