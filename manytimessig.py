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
from crypturd.sha import sha256
from crypturd import onetimesig
import os
import sys

# Properties with default settings

# Signatures:      1.419.840
# Public key:       32 Bytes
# Signature size:   8.84 KiB
# Private key:    126.60 KiB

class PrivateKey():

    def __init__(self, max_sig_size = 9*1024):
        self.depth,self.width = best_depth_width(max_sig_size)
        self.root_key        = onetimesig.new_keys()
        self.node_keys  = [[onetimesig.new_keys()
                            for ind in range(self.width)]
                           for d in range(self.depth)]
        self.node_index      = [0 for d in range(self.depth)]

    def __repr__(self):
        return "<manytimessig %s>"%crypturd.hexstr(self.root_key[0])

    def sign(self,msg):
        "Sign the path to a leaf in the tree and sign using that leaf"
        self.update_counter()
        sk = self.root_key[1]
        sig = chr(self.width)
        for d in range(0,self.depth,1):
            for x in range(self.width):
                sig+=self.node_keys[d][x][0]

            sig+= onetimesig.sign(
                "".join([self.node_keys[d][x][0] for x in range(self.width)])
                ,sk)

            sig+=chr(self.node_index[d])
            sk = self.node_keys[d][self.node_index[d]][1]

        sig += onetimesig.sign(msg,sk)
        return sig

    def signatures_left(self):
        "Return how many message can still be signed"
        n = 0
        for d in range(self.depth):
            n*=self.width
            n+=self.node_index[d]
        return (self.width**self.depth)-n

    def update_counter(self):
        "Count in binary to generate a new path in the tree"
        overflow = True
        for d in range(self.depth-1,-1,-1):
            if overflow:
                if self.node_index[d]==(self.width-1):
                    self.node_index[d] = 0
                else:
                    self.node_index[d] +=1
                    overflow = False
                    for d2 in range(d+1,self.depth,1):
                        self.node_keys[d2]  = [onetimesig.new_keys()
                                               for ind in range(self.width)]
        if overflow:
            for d2 in range(0,self.depth,1):
                self.node_keys[d2]  = [onetimesig.new_keys()
                                       for ind in range(self.width)]
        # for d in range(self.depth):
        #     ind = self.node_index[d]
        #     k = crypturd.common.hexstr(self.node_keys[d][ind][0])[:64]
        #     print "d %2i ind %2i key %s..."%(d,ind,k)

    def PublicKey(self):
        return self.root_key[0]

def verify(msg,sig,pk):
    width,sig = ord(sig[0]),sig[1:]
    slen = onetimesig.signature_size

    while len(sig)>slen:
        keys = []
        for _ in range(width):
            nkey,sig= sig[:32],sig[32:]
            keys.append(nkey)

        ksig,sig = sig[:slen],sig[slen:]

        if not onetimesig.verify("".join(keys),ksig,pk):
            return False
        rsymb,sig = ord(sig[0]),sig[1:]
        pk = keys[rsymb]

    return onetimesig.verify(msg,sig,pk)


def best_depth_width(max_sig_size):
    "find the best depth and width to"
    def sigsize(height,width,slen=onetimesig.signature_size):
        return slen+ (height)*(1+width*32+slen)

    best_d_w = 0,0
    best_sigcount = 0
    for depth in range(1,256):
        for width in range(1,256):
            ssize = sigsize(depth,width)
            if ssize<=max_sig_size:
                if width**depth > best_sigcount:
                    best_sigcount = width**depth
                    best_d_w = depth,width
    return best_d_w
