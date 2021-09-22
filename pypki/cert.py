#!/usr/bin/python
#
# Functions for X.509 encoded objects
#
# @author Brian Hession
# @email github@bhmail.me
#

from __future__ import unicode_literals, division, absolute_import, print_function
import sys
from asn1crypto import (
    core,
    x509
)
from Crypto.PublicKey import (
    ECC,
    RSA
)

from . import (
    error,
    util
)
from .types import HashType


def parse_name_object(nameobj):
    name = list()
    for rdn in nameobj.chosen:
        for type_val in rdn:
            _field = {
                'common_name': 'CN',
                'country_name': 'C',
                'locality_name': 'L',
                'state_or_province_name': 'ST',
                'organization_name': 'O',
                'organizational_unit_name': 'OU',
            }.get(type_val['type'].native, type_val['type'].native)
            _value = type_val['value'].native
            name.append((_field, _value))
    return name


class Certificate(x509.Certificate):
    "Structure defining an ASN.1 Certificate"

    _public_key = None

    @staticmethod
    def from_bytes(cert):
        "Converts the ASN.1 encoded bitstring into and ASN.1 object"
        return Certificate().load(cert)

    @staticmethod
    def from_pem(pem_bytes):
        return Certificate.from_bytes(util.from_pem(pem_bytes))

    @staticmethod
    def from_der(der_bytes):
        return Certificate.from_bytes(der_bytes)

    def to_bytes(self):
        return self.dump()

    def to_der(self):
        return self.to_bytes()

    def to_pem(self):
        return util.to_pem(self.to_bytes(),
                header='-----BEGIN CERTIFICATE-----',
                footer='-----END CERTIFICATE-----')

    def name_hash(self, hash_type=HashType.SHA1):
        """
        hash_func
            function to generate the hash (return value must implement digest())

            ex. return hash_func(msg).digest()
        :return:
            hash of the Subject
        """
        return hash_type.hash(super().subject.dump())

    def key_hash(self, hash_type=HashType.SHA1):
        """
        hash_func
            function to generate the hash (return value must implement digest())

            ex. return hash_func(msg).digest()
        :return:
            hash of the Public Key Info
        """
        return hash_type.hash(bytes(super().public_key['public_key']))

    @property
    def subject(self):
        """
        :return:
            String representing the subject
        """
        return ', '.join(['{}={}'.format(a, b) for a, b in parse_name_object(super().subject)])

    @property
    def issuer(self):
        """
        :return:
            String representing the issuer
        """
        return ', '.join(['{}={}'.format(a, b) for a, b in parse_name_object(super().issuer)])

    @property
    def signature_algo(self):
        """
        :return:
            None or String of the signature algorithm
        """
        _signature_algo = self['signature_algorithm']
        if not _signature_algo:
            return None
        _oid = _signature_algo['algorithm']
        if not _oid:
            return None
        return _oid.map(_oid.dotted)

    @property
    def not_before(self):
        """
        :return:
            DateTime of the Not Before date
        """
        return self.not_valid_before

    @property
    def not_after(self):
        """
        :return:
            DateTime of the Not After date
        """
        return self.not_valid_after

    @property
    def public_key_algo(self):
        """
        :return:
            String containing the key algorithm
        """
        #return self['tbs_certificate']['subject_public_key_info'].algorithm
        return super().public_key.algorithm

    @staticmethod
    def _parse_rsa(asn1obj):
        """
        asn1obj
            PublicKeyInfo ASN.1 object
        :return:
            Crypto.PublicKey.RSA.RsaKey
        """
        _key = asn1obj['public_key'].parsed
        return RSA.construct((_key['modulus'].native, _key['public_exponent'].native))

    @staticmethod
    def _parse_ecc(asn1obj):
        """
        asn1obj
            PublicKeyInfo ASN.1 object
        :return:
            Crypto.PublicKey.ECC.EccKey
        """
        _algoParam = asn1obj['algorithm']['parameters'].native
        x, y = asn1obj['public_key'].to_coords()
        return ECC.construct(curve=_algoParam, point_x=x, point_y=y)

    @property
    def public_key(self):
        """
        :return:
            crypto.rsa.PublicKey or crypto.ecc.Key.Key object
        """
        if not self._public_key:
            _key = super().public_key
            if self.public_key_algo == 'rsa':
                self._public_key = Certificate._parse_rsa(_key)
            elif self.public_key_algo == 'ec':
                self._public_key = Certificate._parse_ecc(_key)
            else:
                assert False, 'Algorithm not supported'
        return self._public_key

    def prettify(self, space=4, file=sys.stdout):
        util.prettify('Certificate', self, space=space, file=file)
