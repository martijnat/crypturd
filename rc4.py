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

#  ____   ____ _  _     _                   _                                  _
# |  _ \ / ___| || |   (_)___   _ __   ___ | |_   ___  ___  ___ _   _ _ __ ___| |
# | |_) | |   | || |_  | / __| | '_ \ / _ \| __| / __|/ _ \/ __| | | | '__/ _ \ |
# |  _ <| |___|__   _| | \__ \ | | | | (_) | |_  \__ \  __/ (__| |_| | | |  __/_|
# |_| \_\\____|  |_|   |_|___/ |_| |_|\___/ \__| |___/\___|\___|\__,_|_|  \___(_)


class rc4_rand(crypturd.common.RngBase):

    "A very simple but insecure random number generator"

    def __init__(self, key=""):
        self.S = list(range(256))
        key = map(ord,key)
        if len(key) > 0:
            j = 0
            for i in range(256):
                j = (j + self.S[i] + key[i % len(key)]) % 256
                self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def rand_int8(self):
        "return a psuedorandom integer mod 256"
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        return self.S[(self.S[self.i] + self.S[self.j]) % 256]

def rc4_encrypt(data,key):
    keystream = ""
    r = rc4_rand(key)
    while len(keystream)<len(data):
        keystream+=chr(r.rand_int8())
    return crypturd.common.xor_str(data,keystream)

rc4_decrypt = rc4_encrypt
