#!/usr/bin/env python2

# Copyright (C) 2017  Martijn Terpstra

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import crypturd
from crypturd.sha import sha256
import os


def new_keys():
    "Generate a public/private keypair for hash-based signatures"
    sk = ""
    digest = ""
    for n in range(256):
        for b in False, True:
            secret = os.urandom(32)
            sk += secret
            digest += sha256(secret)

    pk = sha256(digest)
    return pk, sk


def sign(msg, sk):
    "Sign a 256-bit value"
    msg1 = crypturd.fixed_length_key(msg, 32)
    M1 = crypturd.bigendian2int(msg1)
    sig = ""

    for i in range(256):
        zero = sk[i * 64:i * 64 + 32]
        one  = sk[i * 64 + 32:i * 64 + 64]
        if ((1 << i) & M1) > 0:
            zero = crypturd.sha256(zero)
        else:
            one = crypturd.sha256(one)
        sig += zero + one

    return sig

def verify(msg, sig, pk):
    "verify a 256-bit value using hash-bash signatures"
    msg = crypturd.fixed_length_key(msg, 32)
    digest = ""
    M1 = crypturd.bigendian2int(msg)

    for i in range(256):
        zero = sig[i * 64:i * 64 + 32]
        one  = sig[i * 64 + 32:i * 64 + 64]
        if ((1 << i) & M1) > 0:
            one = crypturd.sha256(one)
        else:
            zero = crypturd.sha256(zero)
        digest += zero + one

    return sha256(digest) == pk
