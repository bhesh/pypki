#!/usr/bin/python3

import os, sys
if __name__ == '__main__':
    SRC_DIR = os.path.dirname(os.path.realpath(__file__))
    sys.path.append(os.path.join(SRC_DIR, '..'))
    from pypki import ocsp
    from pypki.cert import Certificate
    from pypki.types import HashType
    from pypki.verify import verify

def main(args):
    if len(args) != 4:
        print('usage:', args[0], 'url', 'issuer', 'serial')
        return 1

    # Get arguments
    url = args[1]
    issuer = None
    with open(args[2], 'rb') as f:
        issuer = Certificate.from_pem(f.read())
    serial = int(args[3], 16)

    # Build request and get OCSP response
    req = ocsp.OCSPRequestBuilder().with_cert_id(issuer, serial, hash_type=HashType.SHA1).build()
    resp = ocsp.post(url, req, headers={
        'User-Agent' : 'PyPKI/1.0 (+github@bhmail.me)'
    })

    # Print information
    print('Responder status:', resp.status)
    print('Responder ID:', resp.responder_id)
    for c_id in req.request_list:
        print('Certificate status (0x{:X}):'.format(c_id[2]), resp.get_response(c_id).cert_status)
    cert_chain = resp.signing_certificate
    if not cert_chain:
        print('Error: no certificate in response')
        return 2
    print('Signing certificate')
    print('  Subject:', cert_chain[0].subject)
    print('  Issuer:', cert_chain[0].issuer)
    try:
        verify(resp, cert_chain[0])
    except:
        print('Verification failure: OCSP response signature is invalid')
        return 2
    try:
        verify(cert_chain[0], issuer)
    except:
        print('Verification failure: OCSP signing certificate is invalid')
        return 2
    print('Verification successful')

    # Return ok
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
