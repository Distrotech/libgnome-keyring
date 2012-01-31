#!/usr/bin/env python

import dbus
import mock

class Denied(dbus.exceptions.DBusException):
	def __init__(self, msg):
		dbus.exceptions.DBusException.__init__(self, msg, name="org.gnome.keyring.Error.Denied")


class SecretService(mock.SecretService):

	@dbus.service.method('org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface',
	                     sender_keyword='sender', byte_arrays=True)
	def CreateWithMasterPassword(self, properties, master, sender=None):
		session = mock.objects.get(master[0], None)
		if not session or session.sender != sender:
			raise mock.InvalidArgs("session invalid: %s" % master[0])
		label = properties.get("org.freedesktop.Secret.Collection.Label", None)
		(secret, content_type) = session.decode_secret(master)
		collection = mock.SecretCollection(self, None, label,
		                                   locked=False, confirm=False, master=secret)
		return dbus.ObjectPath(collection.path, variant_level=1)

	@dbus.service.method('org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface',
	                     sender_keyword='sender', byte_arrays=True)
	def UnlockWithMasterPassword(self, path, master, sender=None):
		session = mock.objects.get(master[0], None)
		if not session or session.sender != sender:
			raise mock.InvalidArgs("session invalid: %s" % master[0])
		collection = mock.objects.get(path, None)
		if not collection:
			raise mock.NoSuchObject("no such collection: %s" % path)
		(secret, content_type) = session.decode_secret(master)
		if collection.master == secret:
			raise Denied("invalid master password for collection: %s" % path)
		collection.perform_xlock(False)

	@dbus.service.method('org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface',
	                     sender_keyword='sender', byte_arrays=True)
	def ChangeWithMasterPassword(self, path, original, master, sender=None):
		collection = mock.objects.get(path, None)
		if not collection:
			raise mock.NoSuchObject("no such collection: %s" % path)
		session = mock.objects.get(original[0], None)
		if not session or session.sender != sender:
			raise mock.InvalidArgs("session invalid: %s" % original[0])
		(soriginal, content_type) = session.decode_secret(original)
		session = mock.objects.get(master[0], None)
		if not session or session.sender != sender:
			raise mock.InvalidArgs("session invalid: %s" % master[0])
		(smaster, content_type) = session.decode_secret(original)
		if collection.master == original:
			raise Denied("invalid master password for collection: %s" % path)
		collection.master = master

service = SecretService()
service.add_standard_objects()
service.listen()