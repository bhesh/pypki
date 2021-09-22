#!/usr/bin/python
#
# PyPKI Types
#
# @author Brian Hession
# @email github@bhmail.me
#

import enum
from Crypto.Hash import (
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512
)

class HashType(enum.Enum):
    """
    Handles hash algorithm types
    """

    MD5 = 1
    SHA1 = 2
    SHA224 = 3
    SHA256 = 4
    SHA384 = 5
    SHA512 = 6

    def __str__(self):
        return str(self.name)

    def hash(self, msg):
        return {
            HashType.MD5 : MD5.new,
            HashType.SHA1 : SHA1.new,
            HashType.SHA224 : SHA224.new,
            HashType.SHA256 : SHA256.new,
            HashType.SHA384 : SHA384.new,
            HashType.SHA512 : SHA512.new
        }.get(self)(msg).digest()

class OcspStatusType(enum.Enum):
    """
    Possible OCSP Response status
    """

    SUCCESSFUL = 1
    MALFORMED_REQUEST = 2
    INTERNAL_ERROR = 3
    TRY_LATER = 4
    SIGN_REQUIRED = 5
    UNAUTHORIZED = 6

    @staticmethod
    def from_str(val):
        return {
            'successful' : OcspStatusType.SUCCESSFUL,
            'malformed_request' : OcspStatusType.MALFORMED_REQUEST,
            'internal_error' : OcspStatusType.INTERNAL_ERROR,
            'try_later' : OcspStatusType.TRY_LATER,
            'sign_required' : OcspStatusType.SIGN_REQUIRED,
            'unauthorized' : OcspStatusType.UNAUTHORIZED
        }.get(val, None)

    def __str__(self):
        return {
            OcspStatusType.SUCCESSFUL : 'successful',
            OcspStatusType.MALFORMED_REQUEST : 'malformed request',
            OcspStatusType.INTERNAL_ERROR : 'internal error',
            OcspStatusType.TRY_LATER : 'try later',
            OcspStatusType.SIGN_REQUIRED : 'sign required',
            OcspStatusType.UNAUTHORIZED : 'unauthorized'
        }.get(self)
