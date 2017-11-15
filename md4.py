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

from mcrypto.common import rotl_i32 as rotl
from mcrypto.common import _i32

def md4_padding(L):
    appendix = '\x80'
    appendix += '\x00' * ((55 - L) % 64)
    for bitshift in range(0, 64, 8):
        appendix += chr(((L*8) >> bitshift) % 256)
    return appendix


def md4_add_length_padding(m):
    L = len(m)
    return m + md4_padding(L)


def md4(m):
    "MD4 on a complete message"

    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476


    m = md4_add_length_padding(m)

    for offset in range(0, len(m), 64):
        chunk = m[offset:offset + 64]
        X = [0 for _ in range(16)]
        for i in range(0, 16):
            X[i] = ((ord(chunk[i * 4 + 0]) << 0) +
                    (ord(chunk[i * 4 + 1]) << 8) +
                    (ord(chunk[i * 4 + 2]) << 16) +
                    (ord(chunk[i * 4 + 3]) << 24))

        AA = A
        BB = B
        CC = C
        DD = D

        A = round1(A, B, C, D, 0, 3, X)
        D = round1(D, A, B, C, 1, 7, X)
        C = round1(C, D, A, B, 2, 11, X)
        B = round1(B, C, D, A, 3, 19, X)
        A = round1(A, B, C, D, 4, 3, X)
        D = round1(D, A, B, C, 5, 7, X)
        C = round1(C, D, A, B, 6, 11, X)
        B = round1(B, C, D, A, 7, 19, X)
        A = round1(A, B, C, D, 8, 3, X)
        D = round1(D, A, B, C, 9, 7, X)
        C = round1(C, D, A, B, 10, 11, X)
        B = round1(B, C, D, A, 11, 19, X)
        A = round1(A, B, C, D, 12, 3, X)
        D = round1(D, A, B, C, 13, 7, X)
        C = round1(C, D, A, B, 14, 11, X)
        B = round1(B, C, D, A, 15, 19, X)

        A = round2(A, B, C, D, 0, 3, X)
        D = round2(D, A, B, C, 4, 5, X)
        C = round2(C, D, A, B, 8, 9, X)
        B = round2(B, C, D, A, 12, 13, X)
        A = round2(A, B, C, D, 1, 3, X)
        D = round2(D, A, B, C, 5, 5, X)
        C = round2(C, D, A, B, 9, 9, X)
        B = round2(B, C, D, A, 13, 13, X)
        A = round2(A, B, C, D, 2, 3, X)
        D = round2(D, A, B, C, 6, 5, X)
        C = round2(C, D, A, B, 10, 9, X)
        B = round2(B, C, D, A, 14, 13, X)
        A = round2(A, B, C, D, 3, 3, X)
        D = round2(D, A, B, C, 7, 5, X)
        C = round2(C, D, A, B, 11, 9, X)
        B = round2(B, C, D, A, 15, 13, X)

        A = round3(A, B, C, D, 0, 3, X)
        D = round3(D, A, B, C, 8, 9, X)
        C = round3(C, D, A, B, 4, 11, X)
        B = round3(B, C, D, A, 12, 15, X)
        A = round3(A, B, C, D, 2, 3, X)
        D = round3(D, A, B, C, 10, 9, X)
        C = round3(C, D, A, B, 6, 11, X)
        B = round3(B, C, D, A, 14, 15, X)
        A = round3(A, B, C, D, 1, 3, X)
        D = round3(D, A, B, C, 9, 9, X)
        C = round3(C, D, A, B, 5, 11, X)
        B = round3(B, C, D, A, 13, 15, X)
        A = round3(A, B, C, D, 3, 3, X)
        D = round3(D, A, B, C, 11, 9, X)
        C = round3(C, D, A, B, 7, 11, X)
        B = round3(B, C, D, A, 15, 15, X)

        A = _i32(A + AA)
        B = _i32(B + BB)
        C = _i32(C + CC)
        D = _i32(D + DD)

    # Produce the final hash value (little-endian):
    digest = ""
    for h in A, B, C, D:
        for bitshift in 0, 8, 16, 24:
            digest += chr((h >> bitshift) % 256)
    return digest


# helper functions
def F(x, y, z):
    return (x & y) | (~x & z)


def G(x, y, z):
    return (x & y) | (x & z) | (y & z)


def H(x, y, z):
    return x ^ y ^ z


def round1(a, b, c, d, k, s, X):
    return rotl(a + F(b, c, d) + X[k], s)


def round2(a, b, c, d, k, s, X):
    return rotl(a + G(b, c, d) + X[k] + 0x5a827999, s)


def round3(a, b, c, d, k, s, X):
    return rotl(a + H(b, c, d) + X[k] + 0x6ed9eba1, s)

