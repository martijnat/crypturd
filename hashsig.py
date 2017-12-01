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

# Very simple post-quantum hash-based signature scheme. The main
# drawback the fact that public keys **CANNOT** be reused and that its
# private key and signatures are quite large (32kB).

# The public key is H(H(k_0_0||k_0_1), H(k_1_0||k_1_1), H(k_2_0||k_2_1),
# ... , H(k_511_0||k_511_1))

# To sign a 512-bit message to the following for every bit
# If the n-th bit is zero, it is signed by revealing k_n_0 and H(k_n_1)
# If the n-th bit is one, it is signed by revealing H(k_n_0) and k_n_1

# The recommened way to use this is to sign 2 256-bit messages, a hash
# of the data you want to sign and the public key of your next signing
# key.


def public_private_key_pair():
    sk = ""
    digest = ""
    for n in range(512):
        for b in False, True:
            secret = os.urandom(32)
            sk += secret
            digest += sha256(secret)

    pk = sha256(digest)
    return pk, sk


def sign(msg1, msg2, sk):
    msg1 = crypturd.fixed_length_key(msg1, 32)
    msg2 = crypturd.fixed_length_key(msg2, 32)
    sig = ""
    M1 = crypturd.bigendian2int(msg1)
    M2 = crypturd.bigendian2int(msg1)

    for i in range(256):
        zero = sk[i * 64:i * 64 + 32]
        one  = sk[i * 64 + 32:i * 64 + 64]
        if ((1 << i) & M1) > 0:
            zero = crypturd.sha256(zero)
        else:
            one = crypturd.sha256(one)
        sig += zero + one

    for i in range(256):
        zero = sk[i * 64 + 16384:i * 64 + 16416]
        one  = sk[i * 64 + 16416:i * 64 + 16448]
        if ((1 << i) & M2) > 0:
            zero = crypturd.sha256(zero)
        else:
            one = crypturd.sha256(one)
        sig += zero + one

    return sig

def verify(msg1, msg2, sig, pk):
    msg1 = crypturd.fixed_length_key(msg1, 32)
    msg2 = crypturd.fixed_length_key(msg2, 32)
    digest = ""
    M1 = crypturd.bigendian2int(msg1)
    M2 = crypturd.bigendian2int(msg1)

    for i in range(256):
        zero = sig[i * 64:i * 64 + 32]
        one  = sig[i * 64 + 32:i * 64 + 64]
        if ((1 << i) & M1) > 0:
            one = crypturd.sha256(one)
        else:
            zero = crypturd.sha256(zero)
        digest += zero + one

    for i in range(256):
        zero = sig[i * 64 + 16384:i * 64 + 16416]
        one  = sig[i * 64 + 16416:i * 64 + 16448]
        if ((1 << i) & M2) > 0:
            one = crypturd.sha256(one)
        else:
            zero = crypturd.sha256(zero)
        digest += zero + one

    return crypturd.sha256(digest) == pk
