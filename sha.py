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


from mcrypto.common import rotr_i32 as rotr
from mcrypto.common import rotl_i32 as rotl
from mcrypto.common import _i32
from mcrypto.common import shiftr_i32 as shiftr
from mcrypto.common import xor_str
from mcrypto.common import null_padding


def SHA_padding(L):
    appendix = '\x80'
    appendix += '\x00' * ((55 - L) % 64)
    for bitshift in range(64 - 8, -8, -8):
        appendix += chr((L >> bitshift) % 256)
    return appendix

def sha_add_length_padding(m):
    L = len(m)
    return m + SHA_padding(L)

def sha256(m):
    "Sha256 on a complete message"

    # Initialize hash values
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # Initialize array of round constants
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
    # Pre-processing
    m = sha_add_length_padding(m)

    for offset in range(0, len(m), 64):
        chunk = m[offset:offset + 64]
        # The initial values in w[0..63] don't matter
        w = [0 for _ in range(64)]
        # copy chunk into first 16 words w[0..15] of the message schedule array
        for i in range(0, 16):
            w[i] = ((ord(chunk[i * 4 + 0]) << 24) +
                    (ord(chunk[i * 4 + 1]) << 16) +
                    (ord(chunk[i * 4 + 2]) << 8) +
                    (ord(chunk[i * 4 + 3]) << 0))
        # Extend the first 16 words into the remaining 48 words w[16..63] of the
        # message schedule array:
        for i in range(16, 64):
            s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ shiftr(w[i - 15], 3)
            s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ shiftr(w[i - 2], 10)
            w[i] = _i32(w[i - 16] + s0 + w[i - 7] + s1)

        # Initialize working variables to current hash value:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Compression function main loop:
        for i in range(0, 64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = h + S1 + ch + k[i] + w[i]
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = S0 + maj

            h = g
            g = f
            f = e
            e = _i32(d + temp1)
            d = c
            c = b
            b = a
            a = _i32(temp1 + temp2)

        # Add the compressed chunk to the current hash value:
        h0 = h0 + a
        h1 = h1 + b
        h2 = h2 + c
        h3 = h3 + d
        h4 = h4 + e
        h5 = h5 + f
        h6 = h6 + g
        h7 = h7 + h

    # Produce the final hash value (big-endian):
    digest = ""
    for h in h0, h1, h2, h3, h4, h5, h6, h7:
        for bitshift in 24, 16, 8, 0:
            digest += chr((h >> bitshift) % 256)
    return digest


def sha256_hmac(data, key):
    if len(key) > 32:
        key = sha256(key)
    elif key < 32:
        key = null_padding(key, 64)
    o_key_pad = xor_str(key, '\x5c' * 64)
    i_key_pad = xor_str(key, '\x36' * 64)
    return sha256(o_key_pad + sha256(i_key_pad + data))


def add_sha256_hmac(encf):
    def f(data, key):
        ciphertext = encf(data, key)
        hmac = sha256_hmac(ciphertext, key)
        return ciphertext + hmac
    return f


def check_sha256_hmac(decf):
    def f(data, key):
        ciphertext = data[:-32]
        hmac = data[-32:]
        if hmac != sha256_hmac(ciphertext, key):
            raise Exception("Invalid HMAC")
        plaintext = decf(ciphertext, key)
        return plaintext
    return f

def sha1(m):
    # Note 1: All variables are unsigned 32-bit quantities and wrap modulo 232 when calculating, except for
    #      ml, the message length, which is a 64-bit quantity, and
    #      hh, the message digest, which is a 160-bit quantity.
    # Note 2: All constants in this pseudo code are in big endian.
    #         Within each word, the most significant byte is stored in the leftmost byte position

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0


    m = sha_add_length_padding(m)

    for offset in range(0, len(m), 64):
        chunk = m[offset:offset + 64]

        w = [0 for _ in range(80)]
        for i in range(0, 16):
            w[i] = ((ord(chunk[i * 4 + 0]) << 24) +
                    (ord(chunk[i * 4 + 1]) << 16) +
                    (ord(chunk[i * 4 + 2]) << 8) +
                    (ord(chunk[i * 4 + 3]) << 0))

        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for i in range(16,80):
            w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16],1)

            a = h0
            b = h1
            c = h2
            d = h3
            e = h4


        for i in range(0,80):
            if i >=0 and i<20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i >=20 and i<40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i >=40 and i<60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif i >=60 and i<80:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = _i32(rotl(a,5) + f + e + k + w[i])
            e = d
            d = c
            c = rotl(b,30)
            b = a
            a = temp

        h0 = _i32(h0 + a)
        h1 = _i32(h1 + b)
        h2 = _i32(h2 + c)
        h3 = _i32(h3 + d)
        h4 = _i32(h4 + e)

    digest = ""
    for h in h0, h1, h2, h3, h4:
        for bitshift in 24, 16, 8, 0:
            digest += chr((h >> bitshift) % 256)
    return digest
