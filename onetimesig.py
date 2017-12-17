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

def new_keys():
    "Generate a public/private keypair for hash-based signatures"
    # Based of winternitz
    sk = ""
    digest = ""
    # 32 secrets for 32 blocks of 8-bits each
    for n in range(32):
        secret = os.urandom(32)
        sk += secret
        digest+= hash_times(secret,256)
    # 1 checksum block
    checksum_secret = os.urandom(32)
    sk+=checksum_secret
    digest += hash_times(checksum_secret,32*256)
    pk = sha256(digest)
    return pk, sk


def sign(msg, sk):
    "Sign a 256-bit value"
    msg = crypturd.fixed_length_key(msg, 32)
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




# Lamport's uncompressed signature scheme signature scheme

# 1-time usage
# 16 KB Secret key
# 16 KB Signature
# 16 KB Byte Public key

def new_keys_lamport():
    "Generate a public/private keypair for hash-based signatures"
    sk = ""
    pk = ""
    for n in range(256):
        for b in False, True:
            secret = os.urandom(32)
            sk += secret
            pk += sha256(secret)

    return pk, sk


def sign_lamport(msg, sk):
    "Sign a 256-bit value"
    msg1 = crypturd.fixed_length_key(msg, 32)
    M1 = crypturd.littleendian2int(msg1)
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

def verify_lamport(msg, sig, pk):
    "verify a 256-bit value using hash-bash signatures"
    msg = crypturd.fixed_length_key(msg, 32)
    digest = ""
    M1 = crypturd.littleendian2int(msg)

    for i in range(256):
        zero = sig[i * 64:i * 64 + 32]
        one  = sig[i * 64 + 32:i * 64 + 64]
        if ((1 << i) & M1) > 0:
            one = crypturd.sha256(one)
        else:
            zero = crypturd.sha256(zero)
        digest += zero + one

    return digest == pk

# Compressed signature scheme

# Compressed signature/private key is accomplished by signing only 1's
# of the message plus the complement of the hamming weight.

# 1-time usage
# 8448 Byte Secret key
# 8448 Byte Signature
# 32 Byte Public key

def new_keys_compressed():
    "Generate a public/private keypair for hash-based signatures"
    sk = ""
    digest = ""
    # 256 secret values for signing message
    for n in range(256):
        secret = os.urandom(32)
        sk += secret
        digest += sha256(secret)
    # 8 secret for signing hamming weight
    for n in range(8):
        secret = os.urandom(32)
        sk += secret
        digest += sha256(secret)

    pk = sha256(digest)
    return pk, sk


def sign_compressed(msg, sk):
    "Sign a 256-bit value"
    msg = crypturd.fixed_length_key(msg, 32)
    M1 = crypturd.littleendian2int(msg)
    M2 = 8-crypturd.common.hamming_weight(M1)
    M = M1<<256+M2
    sig = ""
    for i in range(256+8):
        secret = sk[i * 32:i * 32 + 32]
        if ((1 << i) & M) > 0:
            sig += crypturd.sha256(secret)
        else:
            sig += secret
    return sig

def verify_compressed(msg, sig, pk):
    "verify a 256-bit value using hash-bash signatures"
    msg = crypturd.fixed_length_key(msg, 32)
    M1 = crypturd.littleendian2int(msg)
    M2 = 8-crypturd.common.hamming_weight(M1)
    M = M1<<256+M2
    digest = ""
    for i in range(256+8):
        block = sig[i * 32:i * 32 + 32]
        if ((1 << i) & M) > 0:
            digest += block
        else:
            digest += crypturd.sha256(block)
    return sha256(digest) == pk

