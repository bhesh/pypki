#!/usr/bin/python3

import sys
if __name__ == '__main__':
    SRC_DIR = os.path.dirname(os.path.realpath(__file__))
    sys.path.append(os.path.join(SRC_DIR, '..'))
    from pypki.crl import CertificateList

def main(args):
    if len(args) != 2:
        print('usage:', args[0], 'CAFile')
        return 1
    cert = None
    with open(args[1], 'rb') as f:
        cert = Certificate.from_pem(f.read())
    print(cert.name_hash().hex())
    print(cert.key_hash().hex())
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
