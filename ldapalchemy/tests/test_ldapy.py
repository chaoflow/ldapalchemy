from __future__ import absolute_import, division, print_function, unicode_literals

import pytest

from .. import ldapy


def test_authenticate(slapd):
    with pytest.raises(ldapy.ParamError) as excinfo:
        ld = ldapy.initialize('wrong_uri')
    assert excinfo.value

    with pytest.raises(ldapy.ServerDown) as excinfo:
        ld = ldapy.initialize('ldapi://nonexistent')
        ldapy.simple_bind_s(ld, 'wrong_dn', 'wrong_pw')
    assert excinfo.value

    with pytest.raises(ldapy.InvalidDNSyntax) as excinfo:
        ld = ldapy.initialize(slapd.ldapi_uri)
        ldapy.simple_bind_s(ld, 'wrong_dn', 'wrong_pw')
    assert excinfo.value

    with pytest.raises(ldapy.InvalidCredentials) as excinfo:
        ld = ldapy.initialize(slapd.ldapi_uri)
        ldapy.simple_bind_s(ld, 'cn=wrong', 'wrong_pw')
    assert excinfo.value

    with pytest.raises(ldapy.InvalidCredentials) as excinfo:
        ld = ldapy.initialize(slapd.ldapi_uri)
        ldapy.simple_bind_s(ld, slapd.bind_dn, 'wrong_pw')
    assert excinfo.value

    ld = ldapy.initialize(slapd.ldapi_uri)
    ldapy.simple_bind_s(ld, slapd.bind_dn, slapd.bind_pw)
    ldapy.unbind(ld)

    ld = ldapy.initialize(slapd.ldap_uri)
    ldapy.simple_bind_s(ld, slapd.bind_dn, slapd.bind_pw)
    ldapy.unbind(ld)

    ld = ldapy.initialize(slapd.ldaps_uri)
    ldapy.simple_bind_s(ld, slapd.bind_dn, slapd.bind_pw)
    ldapy.unbind(ld)

    # use URI defaults from ldaprc
    ld = ldapy.initialize()
    ldapy.simple_bind_s(ld, slapd.bind_dn, slapd.bind_pw)
    ldapy.unbind(ld)
