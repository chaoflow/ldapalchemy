from __future__ import absolute_import, division, print_function, unicode_literals

from libldap import ffi, libldap


from . import exceptions as excs

from .exceptions import *


ERRORS = dict((exc.code, exc) for exc in
              (getattr(excs, name) for name in dir(excs))
              if hasattr(exc, 'code'))


def error(rc, ld=ffi.NULL, ldvalid=True):
    try:
        e = ERRORS[rc](ld=ld, ldvalid=ldvalid)
    except KeyError:
        e = excs.YetUnspecified(rc)

    if ldvalid and ld != ffi.NULL:
        libldap.ldap_unbind(ld)

    raise e


def initialize(uri=None, start_tls=True):
    """Initialize ldap session using LDAPv3

    Return an ldap session handle or raise an LDAPError.

    """
    if uri is not None:
        uri = uri.encode('utf-8')

    # For ldaps tls is started already and for ldapi it makes no sense
    start_tls = start_tls and uri and uri.startswith('ldap:')

    # initialize connection
    ldp = ffi.new('LDAP **')
    rc = libldap.ldap_initialize(ldp, uri if uri is not None else ffi.NULL)
    ld = ldp[0]
    if rc != libldap.LDAP_SUCCESS:
        raise error(rc, ld, ldvalid=False)

    # wrap options properly so they can be passed to initialize
    #
    # XXX: from . import opts; opts.DEBUG_LEVEL
    # or: from ._defines import opts
    #
    # XXX: then again 'man ldap_get_option' is helpful and one could
    # argue to stick here as close as possible to the C API

    # enable logging
    set_option(ld, libldap.LDAP_OPT_DEBUG_LEVEL, libldap.LDAP_DEBUG_ANY)

    # switch to LDAPv3
    set_option(ld, libldap.LDAP_OPT_PROTOCOL_VERSION, libldap.LDAP_VERSION3)

    if start_tls:
        rc = libldap.ldap_start_tls_s(ld, ffi.NULL, ffi.NULL)
        if rc != libldap.LDAP_SUCCESS:
            raise error(rc, ld)

    return ld


def set_option(ld, opt, value):
    if type(value) is int:
        ctype = 'int *'
    else:
        raise TypeError('%s not supported (yet)' % type(value))
    valuep = ffi.new(ctype)
    valuep[0] = value
    rc = libldap.ldap_set_option(ld, opt, valuep)
    if rc != libldap.LDAP_SUCCESS:
        raise error(rc, ld)


def simple_bind_s(ld, dn, pw):
    rc = libldap.ldap_simple_bind_s(ld, dn.encode('utf-8'), pw.encode('utf-8'))
    if rc != libldap.LDAP_SUCCESS:
        raise error(rc, ld)


unbind = libldap.ldap_unbind
