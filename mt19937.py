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

from mcrypto.common import RngBase, unshift_right, unshift_left, _i8, _i32

# __        __               _             _
# \ \      / /_ _ _ __ _ __ (_)_ __   __ _| |
#  \ \ /\ / / _` | '__| '_ \| | '_ \ / _` | |
#   \ V  V / (_| | |  | | | | | | | | (_| |_|
#    \_/\_/ \__,_|_|  |_| |_|_|_| |_|\__, (_)
#                                    |___/
# A Mersenne Twister is not a secure RNG, If you want a secure rng, use
# aes-ctr.


class mt19937(RngBase):

    "Mersenne Twister algorithm based on the Mersenne prime 2**19937 - 1"

    def __init__(self, seed=0):
        self.buf = []
        self.index = 624
        self.mt = [0] * 624
        self.mt[0] = seed
        for i in range(1, 624):
            self.mt[i] = _i32(
                1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

    def update_buffer(self):
        if self.index >= 624:
            self.twist()
        y = self.mt[self.index]

        y = y ^ y >> 11
        y = y ^ y << 7 & 2636928640
        y = y ^ y << 15 & 4022730752
        y = y ^ y >> 18

        self.index = self.index + 1
        self.buf += [_i8(y >> 24), _i8(y >> 16), _i8(y >> 8), _i8(y), ]

    def twist(self):
        for i in range(624):
            y = _i32((self.mt[i] & 0x80000000) +
                     (self.mt[(i + 1) % 624] & 0x7fffffff))
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df
        self.index = 0

    def rand_int8(self):
        "return a psuedorandom integer mod 256"
        if len(self.buf) < 1:
            self.update_buffer()
        r = self.buf[0]
        self.buf = self.buf[1:]
        return r


class mt19937_Clone(mt19937):

    "Clone a mersine prime twister based of 624 outputs"

    def __init__(self, outputs):
        self.buf = []
        self.index = 624
        self.mt = [0] * 624
        for i in range(0, 624):
            y = outputs[i]
            y = unshift_right(y, 18)
            y = unshift_left(y, 15, 4022730752)
            y = unshift_left(y, 7, 2636928640)
            y = unshift_right(y, 11)
            self.mt[i] = y
