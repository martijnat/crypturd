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

import mcrypto
from mcrypto.common import rotl_i32, rotr_i32, _i32,null_padding
from mcrypto.common import int2littleendian,littleendian2int
from mcrypto.common import xor_str
from mcrypto.sha import sha256
from os import urandom

# first 4 intial values of chacha block
constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

# ChaCha quarter round
# a,b,c,d are indexes to 32-bit integers in X
def quarter_round(X, a, b, c, d):
    X[a] = _i32(X[a] + X[b])
    X[d] = rotl_i32(X[d] ^ X[a], 16)
    X[c] = _i32(X[c] + X[d])
    X[b] = rotl_i32(X[b] ^ X[c], 12)
    X[a] = _i32(X[a] + X[b])
    X[d] = rotl_i32(X[d] ^ X[a], 8)
    X[c] = _i32(X[c] + X[d])
    X[b] = rotl_i32(X[b] ^ X[c], 7)


def chacha20_block(key, counter, nonce):
    state = constants + key + counter + nonce
    state_init = [state[i] for i in range(16)]
    for i in range(10):
        quarter_round(state, 0, 4,  8, 12)
        quarter_round(state, 1, 5,  9, 13)
        quarter_round(state, 2, 6, 10, 14)
        quarter_round(state, 3, 7, 11, 15)
        quarter_round(state, 0, 5, 10, 15)
        quarter_round(state, 1, 6, 11, 12)
        quarter_round(state, 2, 7,  8, 13)
        quarter_round(state, 3, 4,  9, 14)

    for i in range(16):
        state[i] = _i32(state[i]+state_init[i])

    return "".join([int2littleendian(state[i],4) for i in range(16)])

def chacha20_encrypt(plaintext,key,counter = 1):
    if len(key)<32:
        key = null_padding(key,32)
    if len(key)>32:
        key = sha256(key)

    key_words = [littleendian2int(key[i:i+4]) for i in range(0,32,4)]
    nonce_words = [littleendian2int(urandom(4)) for _ in range(3)]
    ciphertext = "".join([int2littleendian(n,4) for n in nonce_words])

    for i in range(0,len(plaintext),64):
        j = _i32(i//64)
        key_stream = chacha20_block(key_words,[_i32(counter+j)],nonce_words)
        block = plaintext[i:i+64]
        ciphertext += xor_str(block,key_stream)

    return ciphertext


def chacha20_decrypt(data,key,counter = 1):
    if len(key)<32:
        key = null_padding(key,32)
    if len(key)>32:
        key = sha256(key)

    key_words = [littleendian2int(key[i:i+4]) for i in range(0,32,4)]
    nonce_words = [littleendian2int(data[i:i+4]) for i in range(0,12,4)]
    ciphertext = data[12:]
    plaintext = ""
    for i in range(0,len(ciphertext),64):
        j = _i32(i//64)
        key_stream = chacha20_block(key_words,[_i32(counter+j)],nonce_words)
        block = ciphertext[i:i+64]
        plaintext += xor_str(block,key_stream)

    return plaintext
