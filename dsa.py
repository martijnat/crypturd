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

DSA_DEFAULT_P = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
DSA_DEFAULT_Q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
DSA_DEFAULT_G = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
DSA_DEFAULT_HASH = crypturd.sha.sha256


class DSAKey():

    def __init__(self, p=DSA_DEFAULT_P, q=DSA_DEFAULT_Q, g=DSA_DEFAULT_G, h=DSA_DEFAULT_HASH):
        self.p = p
        self.q = q
        self.g = g
        self.h = h
        self.x = crypturd.random_mod(q)
        self.y = crypturd.modexp(g, self.x, self.p)

    def public(self):
        return DSAPublicKey(self.p, self.q, self.g, self.y, self.h)

    def sign(self, m):
        r = 0
        s = 0
        while s == 0:
            while r == 0:
                k = 2 + crypturd.random_mod(self.q - 2)
                r = crypturd.modexp(self.g, k, self.p)%self.q
            ki = crypturd.modinv(k, self.q)
            s = (ki * (crypturd.littleendian2int(self.h(m)) + self.x * r)) % self.q
        return r, s

    def verify(self, m, pair):
        r, s = pair
        if not (0 < r and r < self.q and 0 < s and s < self.q):
            return False
        w = crypturd.modinv(s, self.q)
        u1 = (crypturd.littleendian2int(self.h(m)) * w) % self.q
        u2 = (r*w)%self.q
        v = ((crypturd.modexp(self.g,u1,self.p)*crypturd.modexp(self.y,u2,self.p))%self.p)%self.q
        return r==v


class DSAPublicKey(DSAKey):

    def __init__(self, p, q, g, y, h):
        self.p = p
        self.q = q
        self.g = g
        self.x = -1             # Anything goes
        self.y = y
        self.h = h
