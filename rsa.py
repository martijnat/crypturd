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
from crypturd.common import decode_tuple,encode_tuple,bigendian2int,int2bigendian

# __        ___    ____  _   _ ___ _   _  ____
# \ \      / / \  |  _ \| \ | |_ _| \ | |/ ___|
#  \ \ /\ / / _ \ | |_) |  \| || ||  \| | |  _
#   \ V  V / ___ \|  _ <| |\  || || |\  | |_| |
#    \_/\_/_/   \_\_| \_\_| \_|___|_| \_|\____|

# This implementation does not check input format. In other
# words: it is vulnerable to ciphertext manipulation.

def gen_public_private_key_pair(bits = 1024):
    p = crypturd.random_prime_mod(2**(bits//2))
    q = crypturd.random_prime_mod(2**(bits//2))
    n = p * q
    e = 2**16+1
    d = None
    while not d:
        try:
            d = crypturd.modinv(e,(p-1)*(q-1))
        except:
            e = (e+1)

    return encode_tuple(e,n),encode_tuple(d,n)

def encrypt_pk(msg,pk):
    "Encrypt string using a RSA public key "
    e,n = decode_tuple(pk)
    m = bigendian2int(msg)
    c = crypturd.modexp(m,e,n)
    return int2bigendian(c)

def decrypt_sk(data,sk):
    "Decrypt string using a RSA private key "
    d,n = decode_tuple(sk)
    c = bigendian2int(data)
    m = crypturd.modexp(c,d,n)
    return int2bigendian(m)

def sign(msg,sk):
    return decrypt_sk(crypturd.sha.sha256(msg),sk)

def verify(msg,sig,pk):
    return bigendian2int(crypturd.sha.sha256(msg)) == bigendian2int(encrypt_pk(sig,pk))
