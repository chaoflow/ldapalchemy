from __future__ import absolute_import, division, print_function, unicode_literals

from ..testing import Slapd
import pytest


@pytest.yield_fixture(scope='session')
def slapd():
    """Manage a slapd instance
    """
    with Slapd() as slapd:
        yield slapd
