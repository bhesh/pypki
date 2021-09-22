# pypki

A Python library for PKI stuff. Currently focused on X.509 and X.843 (OCSP).

## Dependencies

* [pycryptodome](https://pycryptodome.readthedocs.io/en/latest/)
* [asn1crypto](https://pypi.org/project/asn1crypto/)

## Modules

* cert
* crl
* ocsp
* verify
* types
* error

### cert

Classes:

* `Certificate`

### crl

Classes:

* `CertificateList`
* `RevokedCertificate`

### ocsp

Classes:

* `OcspRequest`
* `OcspRequestBuilder`
* `SingleResponse`
* `OcspResponse`

Functions:

* `post(url, request, headers={}, timeout=30) -> OcspResponse`
* `get(url, request, headers={}, timeout=30) -> OcspResponse`

#### post()

Sends the OCSP request as HTTP POST data.

#### get()

Sends the OCSP request via HTTP GET. The request size is limited to IE's 2083 characters.

### verify

Functions:

* `verify(obj, issuer)`

#### verify()

`obj` can be `Certificate`, `CertificateList`, or `OcspResponse`

### types

Classes:

* `HashType`
* `OcspStatusType`

### error

Errors:

* `Error`
* `NotBeforeError`
* `NotAfterError`
* `ThisUpdateError`
* `NextUpdateError`
* `InvalidSignature`
* `RevokedStatusError`
* `UnknownStatusError`

## Contact

Brian Hession: `github@bhmail.me`
