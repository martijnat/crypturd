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

import sys
import time
import os

# Force the use of constant time lookup tables to prevent time based
# side-channel attacks. When enabled, encryption and decryption slow
# down by about factor 100.
ctlt = True

minus1_i32 = 2**32 - 1


def xor_str(s1, s2):
    "xor two strings of equal size"
    return "".join([chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(s1, s2)])


def null_padding(s, n):
    "either truncate or padd with null bytes"
    if len(s) <= n:
        return s + ("\0" * (n - len(s)))
    else:
        return s[:n]


def shiftr_i32(x, n):
    "shift integer n right by b bits"
    return _i32((x & 0xffffffff) >> n)


def shiftl_i32(x, n):
    "shift integer n left by b bits"
    return shiftr_i32(x, (32 - n))


def rotr_i32(x, n):
    "Rotate integer n right by b bits"
    return _i32((((x & 0xffffffff) >> (n & 31)) | (x << (32 - (n & 31)))) & 0xffffffff)


def rotl_i32(x, n):
    "Rotate integer n left by b bits"
    return rotr_i32(x, (32 - n))


def _i8(n):
    return 0xff & n


def _i16(n):
    return 0xffff & n


def _i32(n):
    return 0xffffffff & n


class RngBase():

    "Base class for randum number generators"

    def __init__(self, key=""):
        pass

    def rand_int8(self):
        "return a psuedorandom integer mod 256"
        return 0

    def rand_int16(self):
        "Combine two 8-bit random numbers into a 16 bit value"
        return (self.rand_int8() << 8) + (self.rand_int8())

    def rand_int32(self):
        "Combine two 16-bit random numbers into a 32 bit value"
        return (self.rand_int16() << 16) + (self.rand_int16())

    def rand(self):
        "Return a random float in the range 0-1"
        return float(self.rand_int32()) / float(2**32)


def SilenceErrors(f):
    "Replace any exception by a generic one"
    def SilentFuction(*args, **kwargs):
        RAISE_EXCEPTION = False
        try:
            return f(*args, **kwargs)
        except:
            RAISE_EXCEPTION = True
        if RAISE_EXCEPTION:
            raise Exception("Silenced exception")

    return SilentFuction


def hexstr(s):
    "represpent a string as hex"
    return "".join("%02x" % ord(c) for c in s)


class CTLT():

    """Constant time lookup tables. Expects table of 256 entries of 0-255.
    Significantly slower than normal lookup but limits data leakage
    through cache timing.

    """

    def __init__(self, table):
        self.table = table

    def __getitem__(self, ind):
        if ctlt:
            result = 0x00
            for i in range(256):
                result ^= self.table[ind] & [0, 255][ind == i]
            return result
        else:
            return self.table[ind]


def unshift_right(value, shift):
    result = 0
    for i in range(0, 32 // shift + 1, 1):
        partMask = shiftr_i32(minus1_i32 << (32 - shift), shift * i)
        part = value & partMask
        value = value ^ shiftr_i32(part, shift)
        result = result | part
    return _i32(result)


def unshift_left(value, shift, mask):
    result = 0
    for i in range(0, 32 // shift + 1, 1):
        partMask = shiftr_i32(minus1_i32, (32 - shift)) << (shift * i)
        part = value & partMask
        value = value ^ (part << shift) & mask
        result = result | part
    return _i32(result)

def is_prime(x):
    if x<2:
        return False
    elif x==2:
        return True
    d = 3
    while d*d<=x:
        if x%d==0:
            return False
        d+=2
    return True

def random_mod(x):
    p=1
    while 2**p<x:
        p+=1
    b = (p+7)//8
    r = 0
    for _ in range(b):
        r = r*256 + ord(os.urandom(1))
    r = r%(2**p)
    if r<x:
        return r
    else:
        return random_mod(x)

def random_prime_mod(x):
    r = random_mod(x)
    while not is_prime(r):
        r = random_mod(x)
    return r
