#!/usr/bin/python
#
# Errors
#
# @author Brian Hession
# @email github@bhmail.me
#

from __future__ import unicode_literals, division, absolute_import, print_function

class Error(Exception):
    def __init__(self, msg=None):
        if not msg:
            msg = type(self).__name__
        super(Exception, self).__init__(msg)

class NotBeforeError(Error):
    def __init__(self):
        super(Error, self).__init__('certificate is not yet valid')

class NotAfterError(Error):
    def __init__(self):
        super(Error, self).__init__('certificate is expired')

class ThisUpdateError(Error):
    def __init__(self):
        super(Error, self).__init__('proof is not yet valid')

class NextUpdateError(Error):
    def __init__(self):
        super(Error, self).__init__('proof is expired')

class InvalidSignature(Error):
    def __init__(self):
        super(Error, self).__init__('signature is invalid')

class RevokedStatusError(Error):
    def __init__(self, reason):
        super(Error, self).__init__('certificate is revoked - {}'.format(reason))

class UnknownStatusError(Error):
    def __init__(self):
        super(Error, self).__init__('unknown certificate status')
