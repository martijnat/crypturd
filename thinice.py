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
from os import urandom
from crypturd.common import int2bigendian,bigendian2int,xor_str,fixed_length_key
from crypturd.common import modexp,modinv,random_prime_mod,random_mod,encode_tuple,decode_tuple
from crypturd.pkcs7 import add_padding,remove_padding

# A set of custom non-trivial broken cryptographic primitives

# Includes the following broken/backdoored implementations
# - Hash function
# - Random number generator
# - Signature scheme
# - Symmetric encryption
# - Message authentication codes
# - Key exchange protocol

#Constants

# Exact number of rounds isn't important, 239 was chosen because it is a prime number
THINICE_ROUNDS = 233

#256-bit mask
m256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

# digits of pi
pi_dig = 0x243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89452821e638d01377be5466cf34e90c6cc0ac
# digits of e
e_dig = 0xb7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef324e7738926cfbe5f4bf8d8d8c31d763da06

def hash_int(x,rounds = THINICE_ROUNDS):
    "Hash 256-bit integers, used a helper function for main hash function"
    # WEAK: it is feasable to find a preimage
    y                 = x
    for i in range(rounds):
        y             = ((y<<1)^e_dig)&m256
        x             = (x^(pi_dig*i))&m256
        x             = ((x>>i)|(x<<(256-i)))&m256
        x             = (x+e_dig*i)&m256
    z = (x^y)>>128
    return x^y^z

def hash(data):
    "Hash arbiratey length strings"
    # WEAK: Trivial collissions (even is hash_int is secure)
    # WEAK: Easy length extension attack

    # pad data until its length is a mutlple of 32 bytes/256 bits
    data = data + "\0"*(32-len(data)%32)
    H = hash_int(0)
    # For every 32 byte block, generate a new H
    for i in range(0,len(data),32):
        x = bigendian2int(data[i:i+32])
        H = hash_int(H^x)
    return int2bigendian(H,32)

def encrypt_raw(data,key,iv="\0"*32):
    "Encrypt data"
    # Weak: IV reuse with default parameters
    # Weak: Vulnerable to ciphertex manipulation
    key = fixed_length_key(key,32)
    ciphertext = ""
    data = add_padding(data,32)
    for i in range(0,len(data),32):
        block = data[i:i+32]
        iv = hash(xor_str(iv,key))
        ciphertext+=xor_str(iv,block)
    return ciphertext

def decrypt_raw(data,key,iv="\0"*32):
    "Decrypt data"
    key = fixed_length_key(key,32)
    plaintext = ""
    for i in range(0,len(data),32):
        block = data[i:i+32]
        iv = hash(xor_str(iv,key))
        plaintext+=xor_str(iv,block)
    plaintext = remove_padding(plaintext)
    return plaintext

def mac(H,data,key):
    "Message authentication code"
    # Weak: trivial modification of first data block
    for i in range(0,len(data),32):
        H = hash(xor_str(data[i:i+32],H))
    return H


def encrypt(data,key):
    "Encrypt with random IV and add MAC"
    # mac and encrypy_raw are weak
    iv = urandom(32)
    ciphertext = encrypt_raw(data,key,iv)
    tag = mac(iv,ciphertext,key)
    return iv+ciphertext+tag

def decrypt(data,key):
    "Encrypt with random IV and add MAC"
    iv,ciphertext,tag = data[:32],data[32:-32],data[-32:]
    plaintext = decrypt_raw(ciphertext,key,iv)
    assert tag == mac(iv,ciphertext,key)
    return plaintext

class rand(crypturd.common.RngBase):
    "Generate pseudorandom stream"
    # WEAK: After only a handful of calls the internal state can be reconstructed

    def __init__(self, key=""):
        self.key = hash(key)
        self.seed = urandom(32)
        self.buf = self.seed

    def update_buffer(self):
        self.buf += xor_str(hash(self.seed),self.key)
        self.seed = self.buf

    def rand_int8(self):
        if len(self.buf) < 1:
            self.update_buffer()
        r = ord(self.buf[0])
        self.buf = self.buf[1:]
        return r

def gen_key_pair_sign():
    "Generate a public/private keypair for signing"
    # WEAK: attacker can combine signatures to forge a new signature

    # 16 KB signature
    # 16 KB private key
    # 32 byte public key
    sk = ""
    digest = ""
    for n in range(256):
        for b in False, True:
            secret = urandom(32)
            sk += secret
            digest += hash(secret)

    pk = hash(digest)
    return pk, sk


def sign(msg, sk):
    "Sign an message (arbitrary length string)"
    M = bigendian2int(hash(msg))
    sig = ""
    digest = ""
    for i in range(256):
        zero = sk[i * 64:i * 64 + 32]
        one  = sk[i * 64 + 32:i * 64 + 64]
        if ((1 << i) & M) > 0:
            zero = hash(zero)
        else:
            one = hash(one)
        sig += zero + one

    return sig

def verify(msg, sig, pk):
    "Verify a signature"
    M = bigendian2int(hash(msg))
    digest = ""
    for i in range(256):
        zero = sig[i * 64:i * 64 + 32]
        one  = sig[i * 64 + 32:i * 64 + 64]
        if ((1 << i) & M) > 0:
            one = hash(one)
        else:
            zero = hash(zero)
        digest += zero + one
    return hash(digest) == pk

def gen_key_pair_encrypt(bits=256):
    # Weak: provides nowhere near 256-bits of security
    # Weak: private key can be computed from public key in sub-polynomial time
    P = random_prime_mod(1<<bits)
    n = P*P
    e = random_mod(n)
    d = None
    while not d:
        try:
            d = modinv(e,P*P-P)
        except:
            e = random_mod(n)
            d = None

    # public key, secret key
    # Can be safely swapped
    return encode_tuple(e,n),encode_tuple(d,n)

def gen_key_pair_encrypt(bits=256):
    # Weak: provides nowhere near 256-bits of security
    # Weak: private key can be computed from public key in sub-polynomial time
    P = random_prime_mod(1<<bits)
    n = P*P
    e = random_mod(n)
    d = None
    while not d:
        try:
            d = modinv(e,P*P-P)
        except:
            e = random_mod(n)
            d = None

    # public key, secret key
    # Can be safely swapped
    return encode_tuple(e,n),encode_tuple(d,n)

def encrypt_pk(msg,pk):
    "Encrypt a string using the public key"
    m = bigendian2int(msg)
    e,n = decode_tuple(pk)
    c = modexp(m,e,n)
    return int2bigendian(c)

def decrypt_sk(data,sk):
    "Decrypt a string using the private key"
    c = bigendian2int(data)
    d,n = decode_tuple(sk)
    m = modexp(c,d,n)
    return int2bigendian(m)
