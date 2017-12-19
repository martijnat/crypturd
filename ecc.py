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
import os
import sys
from crypturd.common import modinv, Fraction
# Increase recursion limit to allow for calculations on large numbers
sys.setrecursionlimit(8000)
one = Fraction(1,1)

class EdwardsCurve():
    # x**2 + y**2 = 1 + d*(x**2)*(y**2) (mod p)

    def __init__(self, d, p):
        self.d = d
        self.p = p

    def RandomPoint(self):
        return self.Point_from_seed(os.urandom(256))

    def PointFromSeed(self, seed):
        g = BasePoint
        a = crypturd.common.bigendian2int(seed) %self.p
        return g*a


p25519 = (2**255) - 19
Ed25519 = EdwardsCurve(d=Fraction(121665,121666),
                          p=p25519)

class CurvePoint():

    def __init__(self, x, y, curve=Ed25519):
        if type(x) is int:
            x = Fraction(x,1)
        if type(y) is int:
            y = Fraction(y,1)
        self.x = x
        self.y = y
        self.curve = curve

    def __mul__(self, scalar):
        if scalar == 0:
            return BasePoint
        elif scalar == 1:
            return self
        elif scalar % 2 == 0:
            return (self + self) * (scalar // 2)
        else:
            return self + (self * (scalar - 1))

    def __add__(P1, P2):
        if P1.curve != P2.curve:
            raise Exception('Points belong to different Curve')
        x1, y1 = P1.x, P1.y
        x2, y2 = P2.x, P2.y
        one = Fraction(1,1)
        x3 = (x1 * y2 + y1 * x2) / (one + P1.curve.d * x1 * x2 * y1 * y2)
        y3 = (y1 * y2 - x1 * x2) / (one - P1.curve.d * x1 * x2 * y1 * y2)
        x3 = Fraction(x3%P1.curve.p)
        y3 = Fraction(y3%P1.curve.p)
        return CurvePoint(x3, y3, P1.curve)


BasePoint = CurvePoint(Fraction(0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a,1),
                       Fraction(0x6666666666666666666666666666666666666666666666666666666666666658,1),
                       Ed25519)

def ECDH_calculate_common_secret(pk,
                                 secret,
                                 curve=Ed25519):
    # calculate G*a*b as an integer
    gab = (pk * crypturd.bigendian2int(secret))
    # Convert to string
    common_secret = crypturd.sha.sha256(crypturd.common.int2bigendian(gab.y,32)+
                                        crypturd.common.int2bigendian(gab.x,32))
    return common_secret


def ECDH_public_private_keypair(g=BasePoint,
                                curve=Ed25519):
    sk = os.urandom(32)
    pk = Ed25519.PointFromSeed(sk)
    return pk, sk
