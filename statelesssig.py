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

# Stateless hash based signature based of the many time signature
# scheme This is accomplised by deterministically having 2**164
# of possible signatures and picking a subkey for each signature at
# random. No subkey is every picked twice due to the large keyspace

# Properties with default settings

# Signatures:       4.835.703.278.458.516.698.824.704 (2**84)
# public key:       32 Bytes
# Signature size:   63.85 KiB
# Private key:     2026 KiB

class PrivateKey():
    def __init__(self, masterkey = None, max_sig_size = 64*1024):
        if not masterkey:
            masterkey           = os.urandom(56+onetimesig.signature_size)
        elif len(masterkey)<56+onetimesig.signature_size:
            raise Exception('Invalid master key size (should be at least %i bytes'%(56+onetimesig.signature_size))
        else:
            self.masterkey = masterkey

        self.masterkey  = masterkey
        self.depth,self.width = crypturd.manytimessig.best_depth_width(max_sig_size)
        self.root_key   = onetimesig.new_keys(self.masterkey[56:])
        self.node_keys  = [[(None,None)
                                     for ind in range(self.width)]
                                    for d in range(self.depth)]
        self.node_index = [0 for d in range(self.depth)]

    def __repr__(self):
        return "<statelessssig %s>"%crypturd.hexstr(self.masterkey)

    def sign(self,msg):
        "Sign the path to a leaf in the tree and sign using that leaf"
        self.new_random_path()
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

    def new_random_path(self):
        "Count in binary to generate a new path in the tree"
        # Generate a random path
        for d in range(0,self.depth,1):
            self.node_index[d] = crypturd.common.random_mod(self.width)
        # Generate new keys deterministically for each path
        for d2 in range(0,self.depth,1):
            self.node_keys[d2]  = [onetimesig.new_keys(self.gen_path_seed(d2,ind))
                                   for ind in range(self.width)]

    def gen_path_seed(self,depth,index):
        "Deterministically generate a random seed for a one time signature"
        # Concatinate prefix+index+depth+indexes of previous nodes
        path_str = "Prefix"
        path_str += chr(depth)  # Add depth
        path_str += chr(index)  # Add index
        path_str += "".join([chr(self.node_index[d]) for d in range(0,depth)])

        # Hash
        path_str = crypturd.sha.sha256(path_str)
        # Xor with masterkey
        path_str = crypturd.common.null_padding(path_str,56)
        seed = crypturd.common.xor_str(self.masterkey[:56],path_str)
        # Generate random stream using chacha20
        random = crypturd.chacha20.chacha20_rand(seed)
        return random.rand_bytes(onetimesig.signature_size)





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
