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
import crypturd

# If true, show exceptions
DEBUG = False

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

    def rand_bytes(self,i=1):
        "Return a random sequence of bytes"
        r = ""
        while len(r)<i:
            r += chr(self.rand_int8())
        return r


def SilenceErrors(f):
    "Replace any exception by a generic one"
    def SilentFuction(*args, **kwargs):
        if DEBUG:
            return f(*args, **kwargs)
        else:
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
    if x < 2:
        return False
    elif x == 2:
        return True
    elif x < 2**32:
        d = 3
        while d * d <= x:
            if x % d == 0:
                return False
            d += 2
        return True
    else:
        # fermat primality test
        for n in [2, 3, 5, 7, 11, 13, 17, 19]:
            if modexp(n, x - 1, x) != 1:
                return False
        return True


def random_mod(x):
    p = 1
    while 2**p < x:
        p += 1
    b = (p + 7) // 8
    r = 0
    for _ in range(b):
        r = r * 256 + ord(os.urandom(1))
    r = r % (2**p)
    if r < x:
        return r
    else:
        return random_mod(x)


def random_prime_mod(x):
    r = random_mod(x)
    while not is_prime(r):
        r = random_mod(x)
    return r


def modexp(x, p, n, r = 1):
    while p:
        if p & 1:
            r = (r * x) % n
        p = p >> 1
        x = (x * x) % n
    return r


def int2bigendian(n, minlen=0):
    r = ""
    while n > 0:
        r = chr(n % 256) + r
        n = n // 256
    while len(r) < minlen:
        r = "\0" + r
    while minlen > 0 and len(r) > minlen:
        r = r[1:]
    return r


def int2littleendian(n, minlen=0):
    r = ""
    while n > 0:
        r = r + chr(n % 256)
        n = n // 256
    while len(r) < minlen:
        r = r + "\0"
    while minlen > 0 and len(r) > minlen:
        r = r[:-1]
    return r


def bigendian2int(r):
    n = 0
    while len(r) > 0:
        n = n * 256 + ord(r[0])
        r = r[1:]
    return n


def littleendian2int(r):
    n = 0
    while len(r) > 0:
        n = n * 256 + ord(r[-1])
        r = r[:-1]
    return n


def is_hex(s):
    for c in s:
        if not (c in "0123456789abcdefABCDEF"):
            return False
    return True


def fixed_length_key(key, length):
    "Given a arbirtrary size KEY, return a LENGTH-byte sized output"
    if len(key) < length:
        return null_padding(key, length)
    elif len(key) == length:
        return key
    elif len(key) == length * 2 and is_hex(key):
        return "".join([chr(int(key[i:i + 2], 16))for i in range(0, len(key), 2)])
    elif length == 32:
        return crypturd.sha.sha256(key)
    elif length < 32:
        return crypturd.sha.sha256(key)[:length]
    else:
        return key[:length]


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    else:
        return x % m

def key_split(key,split_count=2):
    "Split secret into several strings"
    l = len(key)
    keys = []
    error = key
    for k in range(split_count-1):
        newkey = os.urandom(l)
        keys.append(newkey)
        error = xor_str(error,newkey)
    return keys+[error]

def key_combine(keys):
    "Recover secret from several strings"
    while len(keys)>1:
        keys = [xor_str(keys[0],keys[1])]+keys[2:]
    return keys[0]


def encode_tuple(r,s):
    "Encode pair of integers as a string"
    R = crypturd.int2bigendian(r)
    S = crypturd.int2bigendian(s)
    return chr(len(R))+R+S

def decode_tuple(pair):
    "Decode string into tuple of integers"
    r = crypturd.bigendian2int(pair[1:ord(pair[0])+1])
    s = crypturd.bigendian2int(pair[ord(pair[0])+1:])
    return r,s

def hamming_weight(x):
    acc = 0
    while x>2:
        if x%2==1:
            acc+=1
        x = x//2
    return acc

def IdentityMatrix(n):
    I = Matrix(n,n)
    for i in range(n):
        I.values[i][i] = 1
    return I


def xor_list(a,b):
    return list([a^b for a,b in zip(a,b)])

class Matrix():
    def __init__(self,height=1,width=1,values = []):
        self.width = width
        self.height = height
        self.values = [[0 for x in range(width)] for y in range(height)]
        for n,v in enumerate(values):
            y = n//width
            x = n%width
            self.values[y][x] = v
    def transposed(self):
        return Matrix(self.width,
                      self.height,
                      [self.values[y][x]
                       for x in range(self.width)
                       for y in range(self.height)])
    def T(self):
        "shorthand for transposed"
        return self.transposed()

    def __add__(a,b):
        assert a.width == b.width
        assert a.height == b.height
        return Matrix(a.height,
                      a.width,
                      [a.values[y][x]+b.values[y][x]
                       for y in range(a.height)
                       for x in range(b.width)])

    def __sub__(a,b):
        return a + b.scale(-1)

    def scale(self,scalar):
        return Matrix(self.height,
                      self.width,
                      [self.values[y][x]*scalar
                       for y in range(self.height)
                       for x in range(self.width)])

    def __mod__(self,n):
        return Matrix(self.height,
                      self.width,
                      [self.values[y][x]%n
                       for y in range(self.height)
                       for x in range(self.width)])

    def __mul__(a,b):
        "matrix multiplication"
        assert a.width == b.height
        return Matrix(a.height,
                      b.width,
                      [sum(
                          a.values[y][z] * b.values[z][x]
                          for z in range(a.width))
                       for y in range(a.height)
                       for x in range(b.width)])

    def __pow__(self,n,m=-1):
        "Assumes a square matrix"
        if m>=0:
            return modexp(self,n,m,IdentityMatrix(self.height))
        elif n==0:
            return IdentityMatrix(self.height)
        elif n%2==0:
            return pow(self*self,n//2,m)
        else:
            return self*pow(self,n-1,m)

    def __getitem__(self,ind):
        return self.values[ind]

    def __setitem__(self,ind,value):
        self.values[ind] = value

    def BinaryInverse(self):
        "Get the inverse of a binary square matrix using guassian elimination"
        l = self.height
        a = [[self.values[y][x] for x in range(self.height)] for y in range(self.height)]
        b = IdentityMatrix(l).values
        # Xor rows with each-other to make each row1 have a hamming weight of 1
        for row1 in range(l):
            for row2 in range(l):
                new_row_a = xor_list(a[row1],a[row2])
                new_row_b = xor_list(b[row1],b[row2])
                # print row1,row2,".",sum(new_row_a),sum(a[row1])
                if sum(new_row_a)<sum(a[row1]) and sum(new_row_a)>0:
                    a[row1] = new_row_a
                    b[row1] = new_row_b

        # Sort rows to reconstruct the idenity matrix
        for row1 in range(l):    # for every row1 check:
            if a[row1][row1] != 1: # If the current row1 is at the wrong place
                for row2 in range(l): # if so check all other row1
                    if a[row2][row1] == 1: # to find the correct row1
                        for x in range(l): # and swap them
                            a[row1][x],a[row2][x] = a[row2][x],a[row1][x]
                            b[row1][x],b[row2][x] = b[row2][x],b[row1][x]

        self_inverse = Matrix(l,l,[b[y][x] for y in range(l) for x in range(l)])%2

        if ((self_inverse*self)%2).values != IdentityMatrix(l).values:
            raise Exception('Matrix is not invertable')
        return self_inverse


    def __repr__(self):
        """Returns ascii table of alligned values"""
        intl = max([len(str(self.values[y][x]))
                    for y in range(self.height)
                    for x in range(self.width)])
        return "\n".join(["|"+
                          " ".join([("%%%ii"%intl)%self.values[y][x]
                                        for x in range(self.width)])
                          +"|"
                          for y in range(self.height)])
    def CompactBinNotation(self):
        """Returns very compact notation for binary matrices"""
        return "/"+" "*self.width+"\\\n"+"\n".join([" "+
                          "".join([" 1"[self.values[y][x]]
                                    for x in range(self.width)])
                          +" "
                          for y in range(self.height)]) + "\n\\"+" "*self.width+"/\n"

def RandomBinaryNonSingularMatrix(n):
    "Returns a n x n binary non-singular matrix. Used in McEliece cryptosystem"
    # WARNING: Produces a sparse low-entropy matrix (otherwise it is exremely slow)
    m     = IdentityMatrix(n)
    for y in range(n):
        for x in range(n):
            bitflip = random_mod(2)
            try:
                m[y][x]^=bitflip
                m.BinaryInverse()
            except:
                m[y][x]^=bitflip

    return m

def RandomPermutationMatrix(n):
    m= IdentityMatrix(n)
    for y1 in range(n):
        y2 = random_mod(y1+1)
        m[y1],m[y2] = m[y2],m[y1]
    return m
