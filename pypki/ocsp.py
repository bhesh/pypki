#!/usr/bin/python
#
# Functions for X.843 encoded objects
#
# @author Brian Hession
# @email github@bhmail.me
#

from __future__ import unicode_literals, division, absolute_import, print_function
import sys
if sys.version_info < (3,):
    from urllib import quote as urlquote
    from urllib2 import (
        Request as URLRequest,
        urlopen
    )

else:
    from urllib.parse import quote as urlquote
    from urllib.request import (
        Request as URLRequest,
        urlopen
    )
from asn1crypto import (
    core,
    algos,
    ocsp,
    x509
)
from Crypto import Random

from . import (
    cert,
    error,
    util
)
from base64 import b64encode
from .types import (
    HashType,
    OcspStatusType
)


class OcspRequest(ocsp.OCSPRequest):

    _request_list = None

    @staticmethod
    def from_bytes(req):
        "Converts the ASN.1 encoded bitstring into and ASN.1 object"
        return OcspRequest().load(req)

    @staticmethod
    def from_pem(pem_bytes):
        return OcspRequest.from_bytes(util.from_pem(pem_bytes))

    @staticmethod
    def from_der(der_bytes):
        return OcspRequest.from_bytes(der_bytes)

    def to_bytes(self):
        return self.dump()

    def to_der(self):
        return self.to_bytes()

    def to_pem(self):
        return util.to_pem(self.to_bytes(),
                header='-----BEGIN OCSP REQUEST-----',
                footer='-----END OCSP REQUEST-----')

    @property
    def request_list(self):
        """
        :return:
            The requests in the format:
                (issuer_name_hash, issuer_key_hash, serial_number)
        """
        if not self._request_list:
            self._request_list = list()
            for req in self['tbs_request']['request_list']:
                _nameHash = req['req_cert']['issuer_name_hash'].native
                _keyHash = req['req_cert']['issuer_key_hash'].native
                _serial = req['req_cert']['serial_number'].native
                self._request_list.append((_nameHash, _keyHash, _serial))
        return self._request_list

    @property
    def nonce(self):
        """
        :return:
            The nonce bitstring
        """
        if self.nonce_value:
            return self.nonce_value.native
        return None

    def prettify(self, space=4, file=sys.stdout):
        util.prettify('OcspRequest', self, space=space, file=file)

    def printCLI(self, prefix='', space=4, file=sys.stdout):
        padding = ' '*space
        print('{}Requests'.format(prefix), file=file)
        for req in self.getRequests():
            print('{}{}Issuer Name Hash:'.format(prefix, padding), req[0].hex(), file=file)
            print('{}{}Issuer Key Hash:'.format(prefix, padding), req[1].hex(), file=file)
            print('{}{}Serial Number: {:X}'.format(prefix, padding, req[2]), file=file)
            print('{}{}--'.format(prefix, padding), file=file)
        if self.getNonce():
            print('{}Nonce:'.format(prefix), self.getNonce().hex(), file=file)


class OcspRequestBuilder:
    "Structure for building an ASN.1 OcspRequest object"

    def __init__(self):
        self.request_list = ocsp.Requests()
        self.request_extns = None
        self.nonce = None

    def with_cert_id(self, cacert, serial, hash_type=HashType.SHA1):
        _hash_algo = algos.DigestAlgorithm()
        _hash_algo['algorithm'] = algos.DigestAlgorithmId(str(hash_type).lower())
        _cert_id = ocsp.CertId()
        _cert_id['hash_algorithm'] = _hash_algo
        _cert_id['issuer_name_hash'] = cacert.name_hash(hash_type)
        _cert_id['issuer_key_hash'] = cacert.key_hash(hash_type)
        _cert_id['serial_number'] = core.Integer(serial)
        _req = ocsp.Request()
        _req['req_cert'] = _cert_id
        self.request_list[len(self.request_list)] = _req
        return self

    def with_nonce(self):
        if not self.request_extns:
            self.request_extns = ocsp.TBSRequestExtensions()
        if not self.nonce:
            self.nonce = Random.get_random_bytes(20)
            _extn = ocsp.TBSRequestExtension()
            _extn['extn_id'] = ocsp.TBSRequestExtensionId(u'nonce')
            _extn['critical'] = True
            _extn['extn_value'] = self.nonce
            self.request_extns[len(self.request_extns)] = _extn
        return self

    def build(self):
        assert len(self.request_list) > 0, 'Must provide at least 1 request'
        _tbs_req = ocsp.TBSRequest()
        _tbs_req['request_list'] = self.request_list
        if self.request_extns:
            _tbs_req['request_extensions'] = self.request_extns
        _ocsp_req = OcspRequest()
        _ocsp_req['tbs_request'] = _tbs_req
        return _ocsp_req


class SingleResponse(ocsp.SingleResponse):
    "Structure defining an ASN.1 OCSP `SingleResponse`"

    _cert_id = None
    _cert_status = None
    _revoked_info = None

    @staticmethod
    def from_bytes(res):
        "Converts the ASN.1 encoded bitstring into and ASN.1 object"
        return SingleResponse().load(res)

    @staticmethod
    def from_pem(pem_bytes):
        return SingleResponse.from_bytes(util.from_pem(pem_bytes))

    @staticmethod
    def from_der(der_bytes):
        return SingleResponse.from_bytes(der_bytes)

    def to_bytes(self):
        return self.dump()

    def to_der(self):
        return self.to_bytes()

    def to_pem(self):
        return util.to_pem(self.to_bytes(),
                header='-----BEGIN OCSP RESPONSE-----',
                footer='-----END OCSP RESPONSE-----')

    @property
    def cert_id(self):
        """
        :return:
            The CertId in the format:
                (issuer_name_hash, issuer_key_hash, serial_number)
        """
        if not self._cert_id:
            _nameHash = self['cert_id']['issuer_name_hash'].native
            _keyHash = self['cert_id']['issuer_key_hash'].native
            _serial = self['cert_id']['serial_number'].native
            self._cert_id = (_nameHash, _keyHash, _serial)
        return self._cert_id

    @property
    def cert_status(self):
        """
        :return:
            good, revoked, or unknown
        """
        if not self._cert_status:
            _status = self['cert_status'].chosen
            if isinstance(_status, ocsp.RevokedInfo):
                self._cert_status = 'revoked'
            else:
                self._cert_status = self['cert_status'].chosen.native
        return self._cert_status

    @property
    def revoked_info(self):
        """
        :return:
            None or the Revoked Info in the format:
                (DateTime of revocation, reason)
        """
        if not self._revoked_info:
            _status = self['cert_status'].chosen
            if not isinstance(_status, ocsp.RevokedInfo):
                return None
            _time = _status['revocation_time'].native
            _reason = _status['revocation_reason']
            if _reason.native:
                _reason = _reason.human_friendly
            else:
                _reason = None
            self._revoked_info = (_time, _reason)
        return self._revoked_info

    @property
    def this_update(self):
        """
        :return:
            DateTime of the This Update time
        """
        return self['this_update'].native

    @property
    def next_update(self):
        """
        :return:
            DateTime of the Next Update time
        """
        return self['next_update'].native

    def prettify(self, space=4, file=sys.stdout):
        util.prettify('OCSPSingleResponse', self, space=space, file=file)

    def printCLI(self, prefix='', space=4, file=sys.stdout):
        padding = ' '*space
        certId = self.getCertId()
        print('{}{}Issuer Name Hash:'.format(prefix, padding), certId[0].hex(), file=file)
        print('{}{}Issuer Key Hash:'.format(prefix, padding), certId[1].hex(), file=file)
        print('{}{}Serial Number: {:X}'.format(prefix, padding, certId[2]), file=file)
        print('{}{}Cert Status:'.format(prefix, padding), self.getCertStatus(), file=file)
        revokedInfo = self.getRevokedInfo()
        if revokedInfo:
            print('{}{}Revoked Info:'.format(prefix, padding), revokedInfo[0], '-', revokedInfo[1], file=file)
        print('{}{}This Update:'.format(prefix, padding), self.getThisUpdate(), file=file)
        print('{}{}Next Update:'.format(prefix, padding), self.getNextUpdate(), file=file)
        try:
            self.isValid()
            print('{}{}Valid: True'.format(prefix, padding), file=file)
        except error.Error as e:
            print('{}{}Valid:'.format(prefix, padding), str(e), file=file)
        print('{}{}--'.format(prefix, padding), file=file)


class OcspResponse(ocsp.OCSPResponse):
    "Structure defining an ASN.1 OcspResponse object"

    _status = None
    _responder_id = None
    _response_list = None
    _signing_cert_chain = None

    @staticmethod
    def from_bytes(res):
        "Converts the ASN.1 encoded bitstring into and ASN.1 object"
        return OcspResponse().load(res)

    @staticmethod
    def from_pem(resFile):
        return OcspResponse.from_bytes(util.from_pem(resFile))

    @staticmethod
    def from_der(resFile):
        return OcspResponse.from_bytes(util.from_der(resFile))

    def to_bytes(self):
        return self.dump()

    def to_der(self, file=sys.stdout):
        util.encodeDERFile(self.to_bytes(), file=file)

    def to_pem(self, file=sys.stdout):
        util.encodePEMFile(self.to_bytes(), file=file,
                header='-----BEGIN OCSP RESPONSE-----',
                footer='-----END OCSP RESPONSE-----')

    @property
    def status(self):
        """
        :return:
            types.OcspStatusType
        """
        if not self._status:
            self._status = OcspStatusType.from_str(self['response_status'].native)
        return self._status

    @property
    def responder_id(self):
        """
        :return:
            String of the Responder ID
        """
        if not self._responder_id:
            _choice = self.response_data['responder_id'].chosen
            if isinstance(_choice, x509.Name):
                self._responder_id = ', '.join(['{}={}'.format(a, b) for a, b in cert.parse_name_object(_choice)])
            else:
                self._responder_id = _choice.native.hex()
        return self._responder_id

    @property
    def produced_at(self):
        """
        :return:
            DateTime of the Produced At time
        """
        return self.response_data['produced_at'].native

    @property
    def nonce(self):
        """
        :return:
            BitString of the nonce
        """
        if self.nonce_value:
            return self.nonce_value.native
        return None

    @property
    def response_list(self):
        """
        :return:
            A list of Response()
        """
        if not self._response_list:
            self._response_list = list()
            for res in self.response_data['responses']:
                res.__class__ = SingleResponse
                self._response_list.append(res)
        return self._response_list

    def get_response(self, cert_id):
        """
        :return:
            None or cert_id's Response
        """
        for resp in self.response_list:
            if cert_id == resp.cert_id:
                return resp
        return None

    @property
    def signing_certificate(self):
        """
        :return:
            None or a List containing the OCSP Signing certificate chain
        """
        if self._signing_cert_chain == None:
            self._signing_cert_chain = list()
            _certchain = self.basic_ocsp_response['certs']
            if not _certchain:
                return None
            for c in _certchain:
                c.__class__ = cert.Certificate
                self._signing_cert_chain.append(c)
        if len(self._signing_cert_chain) > 0:
            return self._signing_cert_chain
        return None

    @property
    def signature_algo(self):
        """
        :return:
            None or a string of the signature algorithm
        """
        _signature_algo = self.basic_ocsp_response['signature_algorithm']
        if not _signature_algo:
            return None
        _oid = _signature_algo['algorithm']
        if not _oid:
            return None
        return _oid.map(_oid.dotted)

    @property
    def signature(self):
        """
        :return:
            None or a BitString of the signature
        """
        _signature = self.basic_ocsp_response['signature']
        if not _signature:
            return None
        return _signature.native

    def prettify(self, space=4, file=sys.stdout):
        util.prettify('OcspResponse', self, space=space, file=file)

    def printCLI(self, filter=None, prefix='', space=4, file=sys.stdout, issuer=None):
        """
        filter
            list if certIDs: (issuer_name_hash, issuer_key_hash, serial)
        space
            indent space size (default: 4)
        file
            file to print to (default: stdout)
        """
        padding = ' '*space
        status = self.getStatus()
        print('{}Response Status:'.format(prefix), status, file=file)
        if status == 'successful':
            print('{}Responder ID:'.format(prefix), self.getResponderId(), file=file)
            print('{}Responses'.format(prefix), file=file)
            for res in self.getResponses():
                certId = res.getCertId()
                if not filter or certId in filter: res.printCLI(prefix=prefix, space=space, file=file)
            if self.getNonce():
                print('{}Nonce:'.format(prefix), self.getNonce().hex(), file=file)

            # Signature
            print('{}Signature Algorithm:'.format(prefix), self.getSignatureAlgorithm(), file=file)
            try:
                signer = self.verifySignature()
                print('{}Signature Verify:'.format(prefix), bool(signer), '-', signer.getSubject(), file=file)
            except error.InvalidOCSPSignature as e:
                print('{}Signature Verify:'.format(prefix), str(e), file=file)

            # Signing certificate
            _certificates = self.getSigningCertificate()
            if not _certificates:
                return
            print('{}OCSP-Signing Certificate Chain'.format(prefix), file=file)
            for c in _certificates:
                print('{}{}Issuer:'.format(prefix, padding), c.getIssuer(), file=file)
                print('{}{}Subject:'.format(prefix, padding), c.getSubject(), file=file)
                print('{}{}Not Before:'.format(prefix, padding), c.getNotBefore(), file=file)
                print('{}{}Not After:'.format(prefix, padding), c.getNotAfter(), file=file)
                try:
                    c.isValid()
                    print('{}{}Valid: True'.format(prefix, padding), file=file)
                except error.Error as e:
                    print('{}{}Valid:'.format(prefix, padding), str(e), file=file)
                if issuer:
                    try:
                        c.verifySignature(issuer)
                        print('{}{}Signature Verify: True'.format(prefix, padding), file=file)
                    except error.InvalidIssuerSignature as e:
                        print('{}{}Signature Verify: False -'.format(prefix, padding), str(e), file=file)
                print('{}{}--'.format(prefix, padding), file=file)


def post(url, ocspReq, headers={}, timeout=30):
    if url[-1] == '/': url = url[:-1]
    data = ocspReq
    if isinstance(ocspReq, OcspRequest):
        data = ocspReq.to_bytes()
    headers['Content-Type'] = 'application/ocsp-request'
    headers['Accept'] = 'application/ocsp-response'
    if len(url) > 2083:
        raise error.Error('url is too long')
    req = URLRequest(url, data=data, headers=headers)
    res = urlopen(req, timeout=timeout)
    if res:
        return OcspResponse.from_bytes(res.read())
    return None


def get(url, ocspReq, headers={}, timeout=30):
    if url[-1] == '/': url = url[:-1]
    data = ocspReq
    if isinstance(ocspReq, OcspRequest):
        data = ocspReq.to_bytes()
    headers['Content-Type'] = 'application/ocsp-request'
    headers['Accept'] = 'application/ocsp-response'
    encoded = urlquote.quote_plus(b64encode(data))
    url_target = '{}/{}'.format(url, encoded)
    if len(url_target) > 2083:
        raise error.Error('url is too long')
    req = URLRequest(url_target, headers=headers)
    res = urlopen(req, timeout=timeout)
    if res:
        return OcspResponse.from_bytes(res.read())
    return None
