# ldap.h and libldap_r.so
export LD_LIBRARY_PATH := ${abspath ./env/lib}
export LIBRARY_PATH := ${LD_LIBRARY_PATH}
export C_INCLUDE_PATH := ${abspath ./env/include}

# slapd, slapadd and virtualenvX.Y in PATH
export PATH := ${abspath ./env/sbin}:${abspath ./env/bin}:${abspath ./env/libexec}:${PATH}

# loglevels for SLAPD_LOGLEVEL, comma-separated
# 1      (0x1 trace) trace function calls
# 2      (0x2 packets) debug packet handling
# 4      (0x4 args) heavy trace debugging (function args)
# 8      (0x8 conns) connection management
# 16     (0x10 BER) print out packets sent and received
# 32     (0x20 filter) search filter processing
# 64     (0x40 config) configuration file processing
# 128    (0x80 ACL) access control list processing
# 256    (0x100 stats) connections, LDAP operations, results (recommended)
# 512    (0x200 stats2) stats log entries sent
# 1024   (0x400 shell) print communication with shell backends
# 2048   (0x800 parse) entry parsing
export SLAPD_LOGLEVEL := stats conns


all: tests test-noplone

bootstrap-no-nix:
	virtualenv-2.7 venv27
	./venv27/bin/pip install zc.buildout==1.7.1
	./venv27/bin/pip install \
          click \
          colorama \
          ipdb \
          plumbum \
          py \
          pytest \
          pytest-cache \
          pytest-pep8 \
          pytest-flakes
	./venv27/bin/python setup.py develop
	touch .env
	touch .venv27

# All dependencies are provided via an nix environment. If your
# environment provides them already, simply 'touch .env' and the nix
# environment should not be build.
#
# NOTE: The nix setup currently only works with the python branch of
# nixpkgs and is at this stage not meant to be reproduced by anybody.
# If you are interested in using this I can push development there.

.env: env.nix
	nix-build env.nix --out-link env
	touch .env


# Virtualenvs are used to install the packages in development
# mode. All python dependencies are taken from the "system" python,
# i.e. the python the virtualenvs are installed in.

.venv27: .env
	virtualenv2.7 --system-site-packages venv27
	./venv27/bin/python setup.py develop
	sed -e 's,#!.*,#!./venv27/bin/python,' <./env/bin/py.test-2.7 >./venv27/bin/py.test
	sed -e 's,#!.*,#!./venv27/bin/python,' <./env/bin/buildout >./venv27/bin/buildout
	chmod +x ./venv27/bin/py.test
	chmod +x ./venv27/bin/buildout
	touch .venv27

# .venv34: .env
# 	virtualenv3.4 --system-site-packages venv34
# 	./venv34/bin/python setup.py develop
# 	sed -e 's,#!.*,#!./venv34/bin/python,' <./env/bin/py.test-3.4 >./venv34/bin/py.test
# 	chmod +x ./venv34/bin/py.test
# 	touch .venv34



# Evaluate pytest with mixed feelings

tests27: .venv27
	./venv27/bin/py.test -rfs --tb native $(ARGS)
	make kill-remaining-slapd

# tests34: .venv34
# 	./venv34/bin/py.test -rfs --tb native $(ARGS)

tests: tests27



# For this to be fun openldap needs not be optimized and not stripped
# of debug symbols, see also env.nix

gdb27: .venv27
	./env/bin/gdb --args ./venv27/bin/python ./venv27/bin/py.test -rfs --tb native -s $(ARGS)



# It happens that a test run fails to stop the started slapd,
# especially when quitting ipdb in contrast to continuing. For now
# manually killing it works and this make target helps.

kill-remaining-slapd:
	${shell test -e .slapd-running && kill -9 $(cat .slapd-running) && rm .slapd-running && echo true}



# buildout for pas.plugins.ldapalchemy tests with plone

bin/buildout: .venv27
	./venv27/bin/buildout bootstrap -o

bin/test: bin/buildout buildout.cfg
	./bin/buildout -v -o
	touch bin/test

test-plone: bin/test
	./bin/test -v -s pas.plugins.ldapalchemy ${ARGS}
	make kill-remaining-slapd

# tests that test the PAS plugin without plone against slapd
test-noplone: bin/test
	./bin/test -v -s pas.plugins.ldapalchemy -t noplone ${ARGS}
	make kill-remaining-slapd



# Take schema files from slapd in nix environment, schema files are
# checked into the repository, this is only used to update to newer
# versions.

update-ldap-schema:
	mkdir -p etc/openldap/schema
	cp env/etc/openldap/schema/* etc/openldap/schema/



# Create a self-signed certificate for slapd tests, cert is checked
# in.

self-signed-cert:
	openssl genrsa -out etc/openldap/key.pem 2048
	openssl req -new -x509 -key etc/openldap/key.pem -out etc/openldap/cert.pem -days 10950



clean:
	git clean -Xdf
