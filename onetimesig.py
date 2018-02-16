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


# The scheme is a Winternitz signature scheme with the following parameters:
# l1 = 32
# l2 = 2
# w = 256
# And SHA256 as its hash function

# Debug code for detecting key-reuse
signature_keys = []
signatures = {}
ASSERT_NO_KEY_REUSE = False

def debug_use_key(msg,key):
    # Code for testing if a signature is used twice
    if ASSERT_NO_KEY_REUSE:
        if sk in signature_keys:
            if not (signatures[sk] == msg):
                raise Exception(' reused one-time key <%s...>'%crypturd.common.hexstr(sk)[:64])
        else:
            signature_keys.append(sk)
            signatures[sk] = msg

signature_size = 32*(32+2)           # signature size in bytes

def hash_times(msg,n=1,h=sha256):
    for _ in range(n):
        msg = h(msg)
    return msg

def new_keys(sk = None):
    "Generate a public/private keypair for hash-based signatures"
    if not sk or len(sk)<32*34:
        sk = os.urandom(32*34)
    pk = ""
    # 32 secrets for 32 blocks of 8-bits each
    for n in range(32):
        pk+= hash_times(sk[n*32:n*32+32],256)
    # 2 checksum blocks
    pk += hash_times(sk[-64:-32],32)
    pk += hash_times(sk[-32:],256)
    return sha256(pk), sk

def sign(msg, sk):
    "Sign a 256-bit value"
    msg = crypturd.fixed_length_key(msg, 32)
    sig = ""
    checksum = 0
    for i in range(32):
        c = ord(msg[i])
        checksum += c
        sig += hash_times(sk[i*32:i*32+32],c)
    # sign a checksum
    sig += hash_times(sk[-64:-32],32 - (checksum//256))
    sig += hash_times(sk[-32:],256 - (checksum%256))
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
    digest += hash_times(sig[-64:-32],checksum//256)
    digest += hash_times(sig[-32:],checksum%256)
    return sha256(digest) == pk
