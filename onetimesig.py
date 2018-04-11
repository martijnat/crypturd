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

# Winternitz signature scheme

# secret key is 33 random 32-bit strings
# Signature = H_n(S_0) ... H_m(S_31) || H_checksum(S_32)

# 1-time usage
# 1056 Byte Secret key
# 1056 Byte Signature
# 32 Byte Public key


signature_size = 1056           # signature size in bytes

def hash_times(msg,n=1,h=sha256):
    for _ in range(n):
        msg = h(msg)
    return msg

def new_keys(sk = None):
    "Generate a public/private keypair for hash-based signatures"
    # Based of winternitz
    if not sk or len(sk)<32*33:
        sk = os.urandom(32*33)
    digest = ""
    # 32 secrets for 32 blocks of 8-bits each
    for n in range(32):
        digest+= hash_times(sk[n*32:n*32+32],256)
    # 1 checksum block
    digest += hash_times(sk[-32:],32*256)
    pk = sha256(digest)
    return pk, sk


signature_keys = []
signatures = {}
ASSERT_NO_KEY_REUSE = False

def sign(msg, sk):
    "Sign a 256-bit value"
    msg = crypturd.fixed_length_key(msg, 32)

    # Code for testing if a signature is used twice
    if ASSERT_NO_KEY_REUSE:
        if sk in signature_keys:
            if not (signatures[sk] == msg):
                raise Exception(' reused one-time key <%s...>'%crypturd.common.hexstr(sk)[:64])
        else:
            signature_keys.append(sk)
            signatures[sk] = msg

    sig = ""
    checksum = 0
    for i in range(32):
        c = ord(msg[i])
        checksum += c
        sig += hash_times(sk[i*32:i*32+32],c)
    sig += hash_times(sk[-32:],32*256-checksum)
    return sig

def verify(msg, sig, pk):
    "verify a 256-bit value using hash-bash signatures"
    msg = crypturd.fixed_length_key(msg, 32)
    checksum = 0
    digest = ""
    for i in range(32):
        c = ord(msg[i])
        checksum += c
        digest += hash_times(sig[i*32:i*32+32],256-c)
    digest += hash_times(sig[-32:],checksum)
    return sha256(digest) == pk
