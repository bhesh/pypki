#!/usr/bin/python
#
# Random utility functions
#
# @author Brian Hession
# @email github@bhmail.me
#

from __future__ import unicode_literals, division, absolute_import, print_function
import os
import sys
from asn1crypto import core as asn
from base64 import (
    b64decode,
    b64encode
)
from textwrap import wrap


def to_pem(bitstr, header=str(), footer=str()):
    return '\n'.join([header] + wrap(b64encode(bitstr).decode('utf-8'), width=64) + [footer])


def from_pem(pem_bytes):
    b64_encoded = str()
    record = False
    for line in pem_bytes.decode('utf-8').split('\n'):
        if record and 'END' not in line:
            b64_encoded += line.strip()
        elif 'BEGIN' in line:
            record = True
        elif 'END' in line:
            record = False
    assert not record and len(b64_encoded) > 0, 'Invalid certificate file'
    return b64decode(b64_encoded)


def prettify(name, asn1obj, space=4, depth=0, file=sys.stdout):
    padding = ' '*space*depth

    # Parse the object if it hasn't been
    if isinstance(asn1obj, (asn.ParsableOctetString, asn.ParsableOctetBitString)):
        asn1obj = asn1obj.parsed

    # Set the name
    if len(name) > 0:
        name = str(name).rstrip('=') + '='
    else:
        name = type(asn1obj).__name__ + '='

    # Print based on object type/structure
    if isinstance(asn1obj, asn.Choice):
        prettify(name, asn1obj.chosen, space=space, depth=depth, file=file)
    elif isinstance(asn1obj, (asn.Sequence, asn.Set)):
        print(padding + name + '{', file=file)
        for k in asn1obj:
            prettify(k, asn1obj[k], space=space, depth=(depth + 1), file=file)
        print(padding + '}', file=file)
    elif isinstance(asn1obj, (asn.SequenceOf, asn.SetOf)):
        print(padding + name + '[', file=file)
        for item in asn1obj:
            prettify('', item, space=space, depth=(depth + 1), file=file)
        print(padding + ']', file=file)
    elif isinstance(asn1obj, asn.ObjectIdentifier):
        if asn1obj.dotted in asn1obj._map:
            print(padding + name + asn1obj._map[asn1obj.dotted], file=file)
        return padding + name + asn1obj.dotted
    elif isinstance(asn1obj, (asn.OctetBitString, asn.OctetString)):
        print(padding + name + asn1obj.native.hex(), file=file)
    elif isinstance(asn1obj, (asn.Null, asn.Void)):
        print(padding + name + type(asn1obj).__name__, file=file)
    else:
        print(padding + name + str(asn1obj.native), file=file)
