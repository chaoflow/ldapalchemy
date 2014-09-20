from __future__ import absolute_import, division, print_function, unicode_literals

from Products.Five import fiveconfigure
from Products.Five import zcml
from Products.PloneTestCase import PloneTestCase as ptc
from Products.PloneTestCase import layer
from Testing import ZopeTestCase as ztc

import unittest

import pas.plugins.ldapalchemy as pkg


ptc.setupPloneSite()


class TestCase(ptc.PloneTestCase):
    class layer(layer.PloneSite):
        @classmethod
        def setUp(cls):
            fiveconfigure.debug_mode = True
            zcml.load_config('configure.zcml', pkg)
            fiveconfigure.debug_mode = False
            ptc.installPackage(pkg.__name__) # , quiet=True)

        @classmethod
        def tearDown(cls):
            pass

    def test_(self):
        self.assertTrue(False)

# def test_suite():
#     return unittest.TestSuite([
#         ztc.FunctionalDocFileSuite(
#             'README.txt', package=pkg.__name__,
#             test_class=TestCase),
#         ])


# if __name__ == '__main__':
#    unittest.main(defaultTest='test_suite')
