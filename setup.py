from setuptools import setup

import ast
import os
import re


# allow being called from anywhere
os.chdir(os.path.abspath(os.path.dirname(__file__)))


_version_re = re.compile(r'__version__\s*=\s*(.*)')
_doc_re = re.compile(r'"""\s*(.*?)\s*\n\s*(.*?)"""', re.S)


with open('ldapalchemy/__init__.py', 'rb') as f:
    _content = f.read().decode('utf-8')
    _doc_match = _doc_re.search(_content)
    description = _doc_match.group(1)
    long_description = _doc_match.group(2)
    version = str(ast.literal_eval(_version_re.search(_content).group(1)))


import libldap


# files = []
# for x in ('README.rst', 'HISTORY.rst'):
#     with open(x) as f:
#         files.append(f.read().decode('utf-8'))
# long_description += '\n\n'.join(files)


setup(
    name='ldapalchemy',
    description=description,
    long_description=long_description,
    author='Florian Friesdorf',
    author_email='flo@chaoflow.net',
    url='http://github.com/chaoflow/ldapalchemy',
    version=version,
    license='BSD 2-clause',
    # XXX: to be split later
    packages=['ldapalchemy', 'pas.plugins.ldapalchemy'],
    ext_modules=[libldap.ffi.verifier.get_extension()],
    namespace_packages=['pas', 'pas.plugins'],
    zip_safe=False,
    install_requires=[
        'setuptools',
        'plumbum',
        'cffi',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Topic :: System :: Shells',
    ])
