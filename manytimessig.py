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
from crypturd.common import merkle_leaf,merkle_node,merkle_tree
import os
import sys

# Properties with default settings

# Signatures:      1.419.840
# Public key:       32 Bytes
# Signature size:   8.84 KiB
# Private key:    126.60 KiB

subtree_width = 17

# To caluclate size just generate an empty one and check
subtree_size = len(str(merkle_tree(['\0'*32 for _ in range(subtree_width)]).prune(0)))

def sign(m,sk):
    "Sign a message using a manytimesig secret key"
    return sk.sign(m)

def verify(msg, sig, pk):
    slen = onetimesig.signature_size
    while len(sig) > slen:
        keys = []
        for _ in range(subtree_width):
            nkey, sig = sig[:32], sig[32:]
            keys.append(nkey)

        ksig, sig = sig[:slen], sig[slen:]

        if not onetimesig.verify("".join(keys), ksig, pk):
            return False
        rsymb, sig = ord(sig[0]), sig[1:]
        pk = keys[rsymb]

    return onetimesig.verify(msg, sig, pk)


class PrivateKey():

    def __init__(self, depth=5):
        self.depth = depth
        self.root_key = onetimesig.new_keys()
        self.node_keys = [[onetimesig.new_keys()
                           for ind in range(subtree_width)]
                          for d in range(self.depth)]
        self.node_index = [0 for d in range(self.depth)]

    def __repr__(self):
        return "<manytimessig %s>" % crypturd.hexstr(self.root_key[0])

    def sign(self, msg):
        "Sign the path to a leaf in the tree and sign using that leaf"
        self.update_counter()
        sk = self.root_key[1]
        sig = ""
        for d in range(0, self.depth, 1):
            for x in range(subtree_width):
                sig += self.node_keys[d][x][0]

            sig += onetimesig.sign(
                "".join([self.node_keys[d][x][0] for x in range(subtree_width)]), sk)

            sig += chr(self.node_index[d])
            sk = self.node_keys[d][self.node_index[d]][1]

        sig += onetimesig.sign(msg, sk)
        return sig

    def signatures_left(self):
        "Return how many message can still be signed"
        n = 0
        for d in range(self.depth):
            n *= subtree_width
            n += self.node_index[d]
        return (subtree_width**self.depth) - n

    def update_counter(self):
        "Count in binary to generate a new path in the tree"
        overflow = True
        for d in range(self.depth - 1, -1, -1):
            if overflow:
                if self.node_index[d] == (subtree_width - 1):
                    self.node_index[d] = 0
                else:
                    self.node_index[d] += 1
                    overflow = False
                    for d2 in range(d + 1, self.depth, 1):
                        self.node_keys[d2] = [onetimesig.new_keys()
                                              for ind in range(subtree_width)]
        if overflow:
            for d2 in range(0, self.depth, 1):
                self.node_keys[d2] = [onetimesig.new_keys()
                                      for ind in range(subtree_width)]
        # for d in range(self.depth):
        #     ind = self.node_index[d]
        #     k = crypturd.common.hexstr(self.node_keys[d][ind][0])[:64]
        #     print "d %2i ind %2i key %s..."%(d,ind,k)

    def PublicKey(self):
        return self.root_key[0]





def key_pair():
    sk = PrivateKey()
    pk = sk.PublicKey()
    return pk, sk
