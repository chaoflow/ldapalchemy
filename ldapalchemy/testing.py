from plumbum import local

import logging
import os
import shutil
import tempfile
import time


# XXX
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('ldapalchemy.testing.Slapd')


# optional environment variables
SLAPD_LOGLEVEL = os.environ.get('SLAPD_LOGLEVEL', 'stats')


class Slapd(object):
    # manager credentials
    bind_dn = 'cn=root,o=o'
    bind_pw = 'pw'

    # uris being served
    ldap_uri = 'ldap://127.0.0.1:12389/'
    ldaps_uri = 'ldaps://127.0.0.1:12636/'
    ldapi_uri = 'ldapi://ldapi'

    # if test run fails to kill slapd, e.g. by quitting ipdb, the
    # Makefile can kill that slapd
    # XXX: consider handling this in here, instead of Makefile
    pidfile = '.slapd-running'

    # running slapd
    proc = None

    def __init__(self):
        self.startdir = os.getcwd()
        # zope test runner hack
        if self.startdir.endswith('parts/test'):
            os.chdir('../..')

        self.projectroot = os.path.abspath(
            os.path.join(os.path.dirname(__file__), '..', '..'))
        self.ldif = os.path.join(os.path.dirname(__file__), 'tests', 'base.ldif')

        # create test directory
        self.tmpdir = tempfile.mkdtemp(prefix='ldapalchemy-')
        self.testdir = os.path.join(self.tmpdir, 'openldap')
        self.datadir = os.path.join(self.testdir, 'data')
        self.slapdconf = os.path.join(self.testdir, 'slapd.conf')
        shutil.copytree('etc/openldap', self.testdir)
        shutil.copyfile('ldaprc', os.path.join(self.testdir, 'ldaprc'))
        os.mkdir(self.datadir)

        self.loglevel = reduce(lambda x, y: x + y,
                               (('-d', x) for x in SLAPD_LOGLEVEL.split()))

        self.slapd = local['slapd']
        self.slapadd = local['slapadd']

    def __enter__(self):
        logging.info("Changing to test directory '%s'", self.testdir)
        os.chdir(self.testdir)

        try:
            self.slapadd("-o", 'syslog=0',
                         "-l", self.ldif,
                         "-f", self.slapdconf,
                         # plumbum does not pay attention to cwd
                         cwd=self.testdir)
        except Exception, e:
            # XXX: is this needed or will __exit__ be called anyway?
            # in zope testrunner we run via setUp/tearDown, not
            # context-manager...
            self.__exit__()
            raise e

        self.proc = self.slapd[
            '-f', self.slapdconf,
            '-s', '0',
            '-h', ' '.join([self.ldapi_uri, self.ldap_uri, self.ldaps_uri])
        ].popen(args=self.loglevel,
                # plumbum does not pay attention to cwd
                cwd=self.testdir)

        with open(self.pidfile, 'wb') as f:
            f.write(str(self.proc.pid))

        ldapsearch = local['ldapsearch']['-D', self.bind_dn, '-w', self.bind_pw,
                                         '-b', 'o=o']

        # Make sure slapd is running and responsive on ldap, ldapi and ldaps
        time.sleep(0.1)
        for x in range(10):
            retcode = ldapsearch['-H', self.ldapi_uri].run(
                retcode=None,
                # plumbum does not pay attention to cwd
                cwd=self.testdir)[0]
            if retcode == 0:
                break
            time.sleep(0.5)

        ldapsearch('-H', self.ldap_uri, '-ZZ', cwd=self.testdir)
        ldapsearch('-H', self.ldaps_uri, cwd=self.testdir)

        return self

    def __exit__(self, exc_type=None, exc_value=None, traceback=None):
        os.chdir(self.startdir)
        if self.proc:
            self.proc.kill()
            self.proc.wait()
        if os.path.exists(self.pidfile):
            os.unlink(self.pidfile)
        shutil.rmtree(self.tmpdir)
