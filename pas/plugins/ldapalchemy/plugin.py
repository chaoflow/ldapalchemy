from Products import PluggableAuthService as PAS

import AccessControl
import zope.interface

# XXX: no real ldapalchemy, yet, but barebone ldapy
from ldapalchemy import ldapy


@zope.interface.implementer(
    PAS.interfaces.plugins.IAuthenticationPlugin)
class Plugin(PAS.plugins.BasePlugin.BasePlugin):
    security = AccessControl.ClassSecurityInfo()
    meta_type = 'LDAPAlchemy Plugin'

    # Tell PAS not to swallow our exceptions, do not use for production
    _dont_swallow_my_exceptions = True

    @security.public
    def authenticateCredentials(self, credentials):
        """see PAS.interfaces.plugins.IAuthenticationPlugin
        """
        login = credentials.get('login')
        pw = credentials.get('password')
        if not (login and pw):
            return None

        # XXX: no real ldapalchemy, yet, but barebone ldapy
        # also for now, we open/close the ldap connection for each call
        ld = ldapy.initialize('ldapi://ldapi')
        login_dn = 'cn=%s,o=o' % login

        try:
            ldapy.simple_bind_s(ld, login_dn, pw)
        except ldapy.InvalidCredentials:
            authinfo = None
        else:
            uid = login
            authinfo = (uid, login)
            ldapy.unbind(ld)

        return authinfo
