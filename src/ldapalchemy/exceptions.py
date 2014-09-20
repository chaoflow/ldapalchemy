"""Exceptions for LDAP errors

There might be exceptions in here that should not be exceptions, but
are result codes one should test for as an expected result code before
raising an exception.

Examples of such non-zero result codes are LDAP_COMPARE_FALSE and
LDAP_COMPARE_TRUE.

"""

from __future__ import absolute_import, division, print_function, unicode_literals

from .libldap import ffi, libldap


class Error(Exception):
    def __init__(self, ld=ffi.NULL, ldvalid=False):
        self.msgs = []

        try:
            self.msgs.append(ffi.string(libldap.ldap_err2string(self.code)))
        except:
            self.msgs.append("Error resolving error code '%s'" % self.code)

        # XXX
        #
        # The LDAP struct is opaque. We need a way to check whether ld
        # is a valid connection, otherwise the get_option call crashes
        # with an assertion error
        #
        # An alternative would be to get a diagnostic message only if
        # sensible. Let's keep an eye on what kind of messages we get.
        #
        # For InvalidDNSyntax err2string return 'Invalid DN Syntax'
        # and diag returns 'invalid DN'. Both don't deliver
        # information beyond the exception name.
        if ldvalid and ld != ffi.NULL:
            diagp = ffi.new('char **')
            libldap.ldap_get_option(ld, libldap.LDAP_OPT_DIAGNOSTIC_MESSAGE,
                                    diagp)
            if diagp[0] != ffi.NULL:
                self.msgs.append(ffi.string(diagp[0]))
                libldap.ldap_memfree(diagp[0])

    @property
    def msg(self):
        return '\n  '.join(self.msgs)

    def __str__(self):
        return self.msg


class YetUnspecified(Error):
    def __init__(self, rc):
        self.code = rc


class OperationsError(Error):
    code = libldap.LDAP_OPERATIONS_ERROR


class ProtocolError(Error):
    code = libldap.LDAP_PROTOCOL_ERROR


class TimelimitExceeded(Error):
    code = libldap.LDAP_TIMELIMIT_EXCEEDED


class SizelimitExceeded(Error):
    code = libldap.LDAP_SIZELIMIT_EXCEEDED


class AuthMethodNotSupported(Error):
    code = libldap.LDAP_AUTH_METHOD_NOT_SUPPORTED


class StrongAuthRequired(Error):
    code = libldap.LDAP_STRONG_AUTH_REQUIRED


class Referral(Error):
    code = libldap.LDAP_REFERRAL


class AdminlimitExceeded(Error):
    code = libldap.LDAP_ADMINLIMIT_EXCEEDED


class UnavailableCriticalExtension(Error):
    code = libldap.LDAP_UNAVAILABLE_CRITICAL_EXTENSION


class ConfidentialityRequired(Error):
    code = libldap.LDAP_CONFIDENTIALITY_REQUIRED


class SaslBindInProgress(Error):
    code = libldap.LDAP_SASL_BIND_IN_PROGRESS


class AttrError(Error):
    pass


class NoSuchAttribute(AttrError):
    code = libldap.LDAP_NO_SUCH_ATTRIBUTE


class UndefinedType(AttrError):
    code = libldap.LDAP_UNDEFINED_TYPE


class InappropriateMatching(AttrError):
    code = libldap.LDAP_INAPPROPRIATE_MATCHING


class ConstraintViolation(AttrError):
    code = libldap.LDAP_CONSTRAINT_VIOLATION


class TypeOrValueExists(AttrError):
    code = libldap.LDAP_TYPE_OR_VALUE_EXISTS


class InvalidSyntax(AttrError):
    code = libldap.LDAP_INVALID_SYNTAX


class NameError(Error):
    pass


class NoSuchObject(NameError):
    code = libldap.LDAP_NO_SUCH_OBJECT


class AliasProblem(NameError):
    code = libldap.LDAP_ALIAS_PROBLEM


class InvalidDNSyntax(NameError):
    code = libldap.LDAP_INVALID_DN_SYNTAX


class AliasDerefProblem(NameError):
    code = libldap.LDAP_ALIAS_DEREF_PROBLEM


class SecurityError(Error):
    pass


class XProxyAuthzFailure(SecurityError):
    code = libldap.LDAP_X_PROXY_AUTHZ_FAILURE


class InappropriateAuth(SecurityError):
    code = libldap.LDAP_INAPPROPRIATE_AUTH


class InvalidCredentials(SecurityError):
    code = libldap.LDAP_INVALID_CREDENTIALS


class InsufficientAccess(SecurityError):
    code = libldap.LDAP_INSUFFICIENT_ACCESS


class ServiceError(Error):
    pass


class Busy(ServiceError):
    code = libldap.LDAP_BUSY


class Unavailable(ServiceError):
    code = libldap.LDAP_UNAVAILABLE


class UnwillingToPerform(ServiceError):
    code = libldap.LDAP_UNWILLING_TO_PERFORM


class LoopDetect(ServiceError):
    code = libldap.LDAP_LOOP_DETECT


class UpdateError(Error):
    pass


class NamingViolation(UpdateError):
    code = libldap.LDAP_NAMING_VIOLATION


class ObjectClassViolation(UpdateError):
    code = libldap.LDAP_OBJECT_CLASS_VIOLATION


class NotAllowedOnNonleaf(UpdateError):
    code = libldap.LDAP_NOT_ALLOWED_ON_NONLEAF


class NotAllowedOnRDN(UpdateError):
    code = libldap.LDAP_NOT_ALLOWED_ON_RDN


class AlreadyExists(UpdateError):
    code = libldap.LDAP_ALREADY_EXISTS


class NoObjectClassMods(UpdateError):
    code = libldap.LDAP_NO_OBJECT_CLASS_MODS


class ResultsTooLarge(UpdateError):
    code = libldap.LDAP_RESULTS_TOO_LARGE


class AffectsMultipleDSAs(UpdateError):
    code = libldap.LDAP_AFFECTS_MULTIPLE_DSAS


class APIError(Error):
    pass


class ServerDown(APIError):
    code = libldap.LDAP_SERVER_DOWN


class LocalError(APIError):
    code = libldap.LDAP_LOCAL_ERROR


class EncodingError(APIError):
    code = libldap.LDAP_ENCODING_ERROR


class DecodingError(APIError):
    code = libldap.LDAP_DECODING_ERROR


class Timeout(APIError):
    code = libldap.LDAP_TIMEOUT


class AuthUnknown(APIError):
    code = libldap.LDAP_AUTH_UNKNOWN


class FilterError(APIError):
    code = libldap.LDAP_FILTER_ERROR


class UserCancelled(APIError):
    code = libldap.LDAP_USER_CANCELLED


class ParamError(APIError):
    code = libldap.LDAP_PARAM_ERROR


class NoMemory(APIError):
    code = libldap.LDAP_NO_MEMORY


class ConnectError(APIError):
    code = libldap.LDAP_CONNECT_ERROR


class NotSupported(APIError):
    code = libldap.LDAP_NOT_SUPPORTED


class ControlNotFound(APIError):
    code = libldap.LDAP_CONTROL_NOT_FOUND


class NoResultsReturned(APIError):
    code = libldap.LDAP_NO_RESULTS_RETURNED


class ClientLoop(APIError):
    code = libldap.LDAP_CLIENT_LOOP


class ReferralLimitExceeded(APIError):
    code = libldap.LDAP_REFERRAL_LIMIT_EXCEEDED


class XConnecting(APIError):
    code = libldap.LDAP_X_CONNECTING
