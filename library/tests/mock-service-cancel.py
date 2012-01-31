#!/usr/bin/env python

import dbus
import mock
import time

class SecretService(mock.SecretService):

	@dbus.service.method('org.freedesktop.Secret.Service')
	def SearchItems(self, attributes):
		time.sleep(0.02)
		return mock.SecretService.SearchItems(self, attributes)

service = SecretService()
service.add_standard_objects()
service.listen()