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
from crypturd import onetimesig,twotimesig
import os
import sys

# Use the two time signature scheme as nodes in a tree to sign many
# messages from the same root/public key.

# You can sign up to 2^depth messages using this scheme

# The default options allow for 4.294.967.296 messages with a 32-byte
# public key and ~1M signatures

class PrivateKey():

    def __init__(self, depth = 32):
        self.depth           = depth
        self.root_key        = twotimesig.new_keys()
        self.node_left_keys  = [twotimesig.new_keys() for d in range(depth)]
        self.node_right_keys = [twotimesig.new_keys() for d in range(depth)]
        self.node_right      = [False for d in range(depth)]

    def sign(self,msg):
        "Sign the path to a leaf in the tree and sign using that leaf"
        sig = ""
        sk = self.root_key[1]
        for d in range(0,self.depth,1):
            sig+=self.node_left_keys[d][0]
            sig+=self.node_right_keys[d][0]
            sig+= twotimesig.sign(self.node_left_keys[d][0],self.node_right_keys[d][0],sk)
            if self.node_right[d]:
                sig+="R"
                sk = self.node_right_keys[d][1]
            else:
                sig+="L"
                sk = self.node_left_keys[d][1]

        sig += twotimesig.sign(msg,"",sk)
        self.update_counter()
        return sig

    def signatures_left(self):
        "Return how many message can still be signed"
        n = 0
        for d in range(self.depth):
            n*=2
            if self.node_right[d]:
                n+=1
        return (2**self.depth)-n

    def update_counter(self):
        "Count in binary to generate a new path in the tree"
        overflow = True
        for d in range(self.depth-1,-1,-1):
            if overflow:
                if self.node_right[d]:
                    self.node_right[d] = False
                    self.node_left_keys[d] = twotimesig.new_keys()
                else:
                    self.node_right[d] = True
                    self.node_right_keys[d] = twotimesig.new_keys()
                    overflow = False
        assert not overflow     # MAXIMUM ALLOWED MESSAGES SIGNED!


    def PublicKey(self):
        return self.root_key[0]

def verify(msg,sig,pk):
    slen = 32768                # lenght of a 2-time signature.
    while len(sig)>slen:
        key_left = sig[:32]
        key_right = sig[32:64]
        ksig = sig[64:64+slen]
        if not twotimesig.verify(key_left,key_right,ksig,pk):
            return False
        sig = sig[64+slen:]
        rsymb = sig[0]
        sig = sig[1:]
        if rsymb == "R":
            pk = key_right
        elif rsymb =="L":
            pk = key_left
        else:
            print "Invalid format"
            return False
    return twotimesig.verify(msg,"",sig,pk)


