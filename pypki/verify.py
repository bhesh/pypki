#!/usr/bin/python
#
# Verify functions
#
# @author Brian Hession
# @email github@bhmail.me
#

from __future__ import unicode_literals, division, absolute_import, print_function
from asn1crypto import core
from Crypto.Hash import (
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512
)
from Crypto.Signature import (
    pkcs1_15,
    DSS
)
from datetime import (
    datetime,
    timezone
)

from .cert import Certificate
from .crl import CertificateList
from .error import InvalidSignature
from .ocsp import OCSPResponse


def rsa_verify(h, sig, key):
    pkcs1_15.new(key).verify(h, sig)


def format_coords(x, y, key):
    """This ensures that x and y are exactly the right size"""
    x_int = int.from_bytes(x, byteorder='big', signed=False)
    y_int = int.from_bytes(y, byteorder='big', signed=False)
    c_len = {
        'NIST P-256' : 32,
        'NIST P-384' : 48,
        'NIST P-521' : 66
    }.get(key.curve)
    x = x_int.to_bytes(c_len, byteorder='big', signed=False) 
    y = y_int.to_bytes(c_len, byteorder='big', signed=False)
    return x + y
    

def ecdsa_verify(h, asn1obj, key):
    """The signature is in an ASN.1 object - SEQ ( [0] INT, [1] INT )"""
    _seq = core.load(asn1obj)
    _sig = format_coords(_seq[0].contents, _seq[1].contents, key)
    DSS.new(key, 'fips-186-3').verify(h, _sig)


def _verify_fail(*args, **kwargs):
    assert False, 'Algorithm not supported'


def _verify(algo, msg, sig, key):
    """
    :return:
        True if signature is valid
    """
    _hash, _verify_func = {
        'md5_rsa'    : (MD5.new, rsa_verify),
        'sha1_rsa'   : (SHA1.new, rsa_verify),
        'sha224_rsa' : (SHA224.new, rsa_verify),
        'sha256_rsa' : (SHA256.new, rsa_verify),
        'sha384_rsa' : (SHA384.new, rsa_verify),
        'sha512_rsa' : (SHA512.new, rsa_verify),
        'md5_ecdsa'    : (MD5.new, ecdsa_verify),
        'sha1_ecdsa'   : (SHA1.new, ecdsa_verify),
        'sha224_ecdsa' : (SHA224.new, ecdsa_verify),
        'sha256_ecdsa' : (SHA256.new, ecdsa_verify),
        'sha384_ecdsa' : (SHA384.new, ecdsa_verify),
        'sha512_ecdsa' : (SHA512.new, ecdsa_verify),
    }.get(algo, (_verify_fail, _verify_fail))
    _verify_func(_hash(msg), sig, key)

def _verify_cert(cert, issuer):
    _now = datetime.now(timezone.utc)
    if not cert.not_before or cert.not_before > _now:
        raise NotBeforeError()
    if not cert.not_after or cert.not_after < _now:
        raise NotAfterError()
    if not cert.signature_algo or not cert.signature:
        raise InvalidSignature()
    _msg = cert['tbs_certificate'].dump()
    try:
        _verify(cert.signature_algo, _msg, cert.signature, issuer.public_key)
    except ValueError:
        raise InvalidSignature()

def _verify_crl(crl, issuer):
    _now = datetime.now(timezone.utc)
    if not crl.this_update or crl.this_update > _now:
        raise ThisUpdateError()
    if not crl.next_update or crl.next_update < _now:
        raise NextUpdateError()
    if not crl.signature_algo or not crl.signature:
        raise InvalidSignature()
    _msg = crl['tbs_cert_list'].dump()
    try:
        _verify(crl.signature_algo, _msg, crl.signature, issuer.public_key)
    except ValueError:
        raise InvalidSignature()

def _verify_ocsp(ocsp, issuer, filter=None):
    _now = datetime.now(timezone.utc)

    # Check all responses
    for res in ocsp.response_list:
        if not filter or res.cert_id in filter:
            if not res.this_update or res.this_update > _now:
                raise ThisUpdateError()
            if not res.next_update or res.next_update < _now:
                raise NextUpdateError()
            if not res.cert_status or res.cert_status == 'unknown':
                raise UnknownStatusError()
            if res.cert_status == 'revoked':
                if res.revoked_info:
                    raise RevokedStatusError(res.revoked_info[1])
                raise RevokedStatusError(None)

    # Check signature
    if not ocsp.signature_algo or not ocsp.signature:
        raise InvalidSignature()
    _msg = ocsp.basic_ocsp_response['tbs_response_data'].dump()
    try:
        _verify(ocsp.signature_algo, _msg, ocsp.signature, issuer.public_key)
    except ValueError:
        raise InvalidSignature()

def verify(obj, issuer):
    """
    response
        accepted objects: Certificate, CertificateList, OCSPResponse
    issuer
        Certificate
    :raises:
        InvalidSignature, NotBeforeError, NotAfterError, ThisUpdateError,
        NextUpdateError, RevokedStatusError, UnknownStatusError
    """
    if isinstance(obj, Certificate):
        _verify_cert(obj, issuer)
    elif isinstance(obj, CertificateList):
        _verify_crl(obj, issuer)
    elif isinstance(obj, OCSPResponse):
        _verify_ocsp(obj, issuer)
    else:
        assert False, 'invalid object'
