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

# Use the two time signature scheme as nodes in a tree to sign many
# messages from the same root/public key.

# You can sign up to 2^depth messages using this scheme

# The default options allow for 4.194.304 messages with a 32-byte
# public key and 195 KiB signatures

class PrivateKey():

    def __init__(self, depth = 22):
        self.depth           = depth
        self.root_key        = onetimesig.new_keys()
        self.node_left_keys  = [onetimesig.new_keys() for d in range(depth)]
        self.node_right_keys = [onetimesig.new_keys() for d in range(depth)]
        self.node_right      = [False for d in range(depth)]

    def fromstr(self,s):
        sksize               = 32768
        pksize               = 32
        self.depth           = ord(s[0])
        s                    = s[1:]
        self.root_key        = s[:pksize],s[pksize:pksize+sksize]
        s                    = s[pksize+sksize:]
        self.node_left_keys  = [None for d in range(self.depth)]
        self.node_right_keys = [None for d in range(self.depth)]
        self.node_right      = [False for d in range(self.depth)]

        for d in range(self.depth):
            sk,pk = s[:pksize],s[pksize:pksize+sksize]
            s = s[pksize+sksize:]
            self.node_left_keys[d] = sk,pk

        for d in range(self.depth):
            offset = (pksize+sksize)*d
            sk,pk = s[:pksize],s[pksize:pksize+sksize]
            s = s[pksize+sksize:]
            self.node_right_keys[d] = sk,pk

        for d in range(self.depth):
            if s[d] == "R":
                self.node_right[d] = True
            elif  s[d] == "L":
                self.node_right[d] = False
            else:
                assert False

    def __repr__(self):
        s = [chr(self.depth)]
        for pk,sk in [self.root_key]+self.node_left_keys+self.node_right_keys:
            s.append(pk)
            s.append(sk)
        for lr in self.node_right:
            if lr:
                s.append("R")
            else:
                s.append("L")
        return "".join(s)


    def sign(self,msg):
        "Sign the path to a leaf in the tree and sign using that leaf"
        sig = ""
        sk = self.root_key[1]
        for d in range(0,self.depth,1):
            sig+=self.node_left_keys[d][0]
            sig+=self.node_right_keys[d][0]
            sig+= onetimesig.sign(self.node_left_keys[d][0]+self.node_right_keys[d][0],sk)
            if self.node_right[d]:
                sig+="R"
                sk = self.node_right_keys[d][1]
            else:
                sig+="L"
                sk = self.node_left_keys[d][1]

        sig += onetimesig.sign(msg,sk)
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
        for d in range(self.depth-2,-1,-1):
            if overflow:
                if self.node_right[d]:
                    self.node_right[d] = False
                else:
                    self.node_right[d] = True
                    overflow = False
                    for d2 in range(d+1,self.depth,1):
                        self.node_left_keys[d2]  = onetimesig.new_keys()
                        self.node_right_keys[d2] = onetimesig.new_keys()
        assert not overflow     # MAXIMUM ALLOWED MESSAGES SIGNED!


    def PublicKey(self):
        return self.root_key[0]

def verify(msg,sig,pk):
    # slen = 32768                # lenght of a 2-time signature.
    slen = 8448                 # Length of a compressed lamport signature
    while len(sig)>slen:
        key_left = sig[:32]
        key_right = sig[32:64]
        ksig = sig[64:64+slen]
        if not onetimesig.verify(key_left+key_right,ksig,pk):
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
    return onetimesig.verify(msg,sig,pk)


