#!/usr/bin/python3

import os, sys
if __name__ == '__main__':
    SRC_DIR = os.path.dirname(os.path.realpath(__file__))
    sys.path.append(os.path.join(SRC_DIR, '..'))
    from pypki.cert import Certificate
    from pypki.crl import CertificateList
    from pypki.verify import verify

def main(args):
    if len(args) != 3:
        print('usage:', args[0], 'crl', 'issuer')
        return 1
    crl = None
    with open(args[1], 'rb') as f:
        crl = CertificateList.from_der(f.read())
    ca = None
    with open(args[2], 'rb') as f:
        ca = Certificate.from_pem(f.read())
    print('2141:', crl.get_revoked(2141))
    print('2142:', crl.get_revoked(2142))
    verify(crl, ca)
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
