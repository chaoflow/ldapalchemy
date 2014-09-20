"""pythonic ldap

Work in Progress
"""

__author__ = 'Florian Friesdorf <flo@chaoflow.net>'
__version__ = '0.20140726'


import ctypes as ct


libldap = ct.CDLL('libldap.so')
