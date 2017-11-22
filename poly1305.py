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
from mcrypto.common import fixed_length_key,littleendian2int,int2littleendian

def clamp(r):
    "Helper function for poly1305"
    return r & 0x0ffffffc0ffffffc0ffffffc0fffffff


def poly1305(data, key):
    "Poly1305 message authentication code"
    r = littleendian2int(key[:16])
    r = clamp(r)
    s = littleendian2int(key[16:])
    accumulator = 0
    p = (1 << 130) - 5

    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        n = littleendian2int(block)
        onebit = 2**(len(block) * 8)
        n = n + onebit
        accumulator += n
        accumulator = (r * accumulator) % p

    accumulator += s
    tag = int2littleendian(accumulator, 16)[:16]
    return tag


def poly1305_key_gen(key, nonce):
    counter = 0
    key_words = [littleendian2int(key[i:i + 4]) for i in range(0, 32, 4)]
    nonce_words = [littleendian2int(nonce[i:i + 4]) for i in range(0, 12, 4)]
    block = mcrypto.chacha20_block(key_words, [counter], nonce_words)
    return block[:32]


def add_poly1305_mac(encf):
    def f(data, key):
        key = fixed_length_key(key, 32)
        ciphertext = encf(data, key)
        nonce = ciphertext[:12]
        otk = poly1305_key_gen(key, nonce)
        tag = poly1305(ciphertext, otk)
        return ciphertext + tag
    return f


def check_poly1305_mac(decf):
    def f(data, key):
        key = fixed_length_key(key, 32)
        ciphertext = data[:-16]
        nonce = ciphertext[:12]
        otk = poly1305_key_gen(key, nonce)

        tag = data[-16:]
        if tag != poly1305(ciphertext, otk):
            raise Exception("Invalid MAC (Poly1305)")
        plaintext = decf(ciphertext, key)
        return plaintext
    return f
