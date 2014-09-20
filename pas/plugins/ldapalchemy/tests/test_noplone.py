from __future__ import absolute_import, division, print_function, unicode_literals

import unittest

from ldapalchemy.testing import Slapd
from ..plugin import Plugin


class TestCase(unittest.TestCase):
    # XXX: zope testrunner ignores setUpClass and setUpModule?!
    # Well, slapd is not expensive and there are not many tests, yet...
    #@classmethod
    #def setUpClass(cls):
    def setUp(self):
        self.slapd = Slapd()
        self.slapd.__enter__()

    # @classmethod
    # def tearDownClass(cls):
    def tearDown(self):
        self.slapd.__exit__()

    def test_(self):
        plugin = Plugin()

        auth = plugin.authenticateCredentials(dict(login='wrong', password='wrong'))
        self.assertIsNone(auth)

        auth = plugin.authenticateCredentials(dict(login='root', password='pw'))
        self.assertIsNotNone(auth)
