#!/usr/bin/python
#
# Functions for CRL encoded objects
#
# @author Brian Hession
# @email github@bhmail.me
#

from __future__ import unicode_literals, division, absolute_import, print_function
import sys
if sys.version_info < (3,):
    from urllib2 import (
        Request as URLRequest,
        urlopen
    )

else:
    from urllib.request import (
        Request as URLRequest,
        urlopen
    )
from asn1crypto import crl
from Crypto.Hash import SHA256

from . import (
    cert,
    error,
    util
)


class RevokedCertificate(crl.RevokedCertificate):
    "Structure defining an ASN.1 Revoked Certificate entry"

    @staticmethod
    def from_bytes(cert):
        "Converts the ASN.1 encoded bitstring into and ASN.1 object"
        return RevokedCertificate().load(cert)

    @staticmethod
    def from_pem(pem_bytes):
        return RevokedCertificate.from_bytes(util.from_pem(pem_bytes))

    @staticmethod
    def from_der(der_bytes):
        return RevokedCertificate.from_bytes(der_bytes)

    def to_bytes(self):
        return self.dump()

    def to_der(self):
        return self.to_bytes()

    def to_pem(self):
        return util.to_pem(self.to_bytes(),
                header='-----BEGIN REVOKED CERTIFICATE-----',
                footer='-----END REVOKED CERTIFICATE-----')

    @property
    def issuer(self):
        """
        :return:
            String representing the issuer
        """
        if self.issuer_name:
            return ', '.join(['{}={}'.format(a, b) for a, b in cert.parse_name_object(self.issuer_name)])
        return None

    @property
    def serial(self):
        """
        :return:
            Integer of the serial number
        """
        if not self['user_certificate']:
            return self['user_certificate'].native
        return None

    @property
    def date(self):
        """
        :return:
            DateTime of the revocation date
        """
        if not self['revocation_date']:
            return self['revocation_date'].native
        return None

    @property
    def reason(self):
        """
        :return:
            String representing the reason of revocation
        """
        if not self.crl_reason_value:
            return self.crl_reason_value.native
        return None

    def prettify(self, space=4, file=sys.stdout):
        util.prettify('RevokedCertificate', self, space=space, file=file)

    def printCLI(self, prefix='', space=4, file=sys.stdout):
        padding = ' '*space
        print('{}RevokedCertificate'.format(prefix), file=file)
        print('{}{}Serial:'.format(prefix, padding), '{:X}'.format(self.getSerial()), file=file)
        print('{}{}Date:'.format(prefix, padding), self.getDate(), file=file)
        print('{}{}Reason:'.format(prefix, padding), self.getReason(), file=file)


class CertificateList(crl.CertificateList):
    "Structure defining an ASN.1 CRL"

    _revoked_list = None

    @staticmethod
    def from_bytes(cert):
        "Converts the ASN.1 encoded bitstring into and ASN.1 object"
        return CertificateList().load(cert)

    @staticmethod
    def from_pem(pem_bytes):
        return CertificateList.from_bytes(util.from_pem(pem_bytes))

    @staticmethod
    def from_der(der_bytes):
        return CertificateList.from_bytes(der_bytes)

    def to_bytes(self):
        return self.dump()

    def to_der(self):
        return self.to_bytes()

    def to_pem(self):
        return util.to_pem(self.to_bytes(),
                header='-----BEGIN X509 CRL-----',
                footer='-----END X509 CRL-----')

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
    def this_update(self):
        """
        :return:
            DateTime of the This Update date
        """
        return self['tbs_cert_list']['this_update'].native

    @property
    def next_update(self):
        """
        :return:
            DateTime of the Next Update date
        """
        return self['tbs_cert_list']['next_update'].native

    @property
    def issuer(self):
        """
        :return:
            String representing the issuer
        """
        return ', '.join(['{}={}'.format(a, b) for a, b in cert.parse_name_object(super().issuer)])

    @property
    def revoked_list(self):
        """
        :return:
            List of RevokedCertificate ASN.1 objects
        """
        if not self._revoked_list:
            self._revoked_list = list()
            for rc in self['tbs_cert_list']['revoked_certificates']:
                rc.__class__ = RevokedCertificate
                self._revoked_list.append(rc)
        return self._revoked_list

    def get_revoked(self, certificate):
        """
        certificate
            Certificate ASN.1 object or serial number
        :return:
            True if the certificate is on the list
        """
        if isinstance(certificate, cert.Certificate):
            for rc in self.revoked_list:
                if rc.issuer == certificate.issuer and rc.serial == certificate.serial:
                    return rc
        elif isinstance(certificate, int):
            for rc in self.revoked_list:
                if rc.serial == certificate:
                    return rc
        return None

    def prettify(self, space=4, file=sys.stdout):
        util.prettify('CertificateList', self, space=space, file=file)

#    def printCLI(self, prefix='', space=4, file=sys.stdout):
#        padding = ' '*space
#        print('{}CertificateList'.format(prefix), file=file)
#        print('{}{}SHA-256 Fingerprint:'.format(prefix, padding), SHA256.new(self.dump()).digest().encode('hex'), file=file)
#        print('{}{}Issuer:'.format(prefix, padding), self.getIssuer(), file=file)
#        print('{}{}This Update:'.format(prefix, padding), self.getThisUpdate(), file=file)
#        print('{}{}Next Update:'.format(prefix, padding), self.getNextUpdate(), file=file)
#        try:
#            self.isValid()
#            print('{}{}Valid: True'.format(prefix, padding), file=file)
#        except error.Error as e:
#            print('{}{}Valid:'.format(prefix, padding), str(e), file=file)
#        for rc in self.getRevokedCertificates(): rc.printCLI(prefix=prefix, space=space, file=file)
#
#
#def downloadCRL(url, outFile=None, progressnotifier=None, blocksize=1024, headers={}):
#    """
#    :return:
#        CertificateList ASN.1 object
#    """
#
#    # Open HTTP connection
#    headers['Accept'] = 'application/pkix-crl'
#    req = URLRequest(url, headers=headers)
#    res = urlopen(req, timeout=1)
#
#    # Download in chunks
#    totalBytes = int(res.info().getheader('Content-Length').strip())
#    bytesRead = 0
#    data = str()
#    while bytesRead < totalBytes:
#
#        # Read chunk
#        bytesToRead = blocksize
#        if totalBytes - bytesRead < bytesToRead:
#            bytesToRead = totalBytes - bytesRead
#        data += res.read(bytesToRead)
#        bytesRead = len(data)
#
#        # Update progress
#        if progressnotifier: progressnotifier(bytesRead, totalBytes)
#
#    # Write file to disk, if desired
#    if outFile:
#        with open(outFile, 'w') as f:
#            f.write(data)
#
#    return CertificateList.from_bytes(data)
