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

import mcrypto

# __        ___    ____  _   _ ___ _   _  ____
# \ \      / / \  |  _ \| \ | |_ _| \ | |/ ___|
#  \ \ /\ / / _ \ | |_) |  \| || ||  \| | |  _
#   \ V  V / ___ \|  _ <| |\  || || |\  | |_| |
#    \_/\_/_/   \_\_| \_\_| \_|___|_| \_|\____|

# This implementation does not check input format. In other
# words: it is vulnerable to ciphertext manipulation.

def gen_public_private_key_pair(bits = 2048):
    p = mcrypto.random_prime_mod(2**(bits//2))
    q = mcrypto.random_prime_mod(2**(bits//2))
    n = p * q
    e = 2**16+1
    d = None
    while not d:
        try:
            d = mcrypto.modinv(e,(p-1)*(q-1))
        except:
            e = (e+1)

    return PublicKey(e,n),PrivateKey(e,d,n)

class PublicKey():
    def __init__(self,e,n):
        self.e = e
        self.n =n
    def encrypt(self,msg):
        m = mcrypto.littleendian2int(msg)
        c = mcrypto.modexp(m,self.e,self.n)
        return mcrypto.int2littleendian(c)
    def verify(self,msg,sig):
        return self.encrypt(sig) == mcrypto.sha256(msg)
    def __repr__(self):
        return "=====BEGIN RSA PUBLIC KEY=====\ne=%x\nn=%x\n=====END RSA PUBLIC KEY====="%(self.e,self.n)

class PrivateKey(PublicKey):
    def __init__(self,e,d,n):
        self.e = e
        self.d = d
        self.n = n
    def decrypt(self,msg):
        c = mcrypto.littleendian2int(msg)
        m = mcrypto.modexp(c,self.d,self.n)
        return mcrypto.int2littleendian(m)
    def sign(self,msg):
        m = mcrypto.sha256(msg)
        sig = self.decrypt(m)
        return sig


    def __repr__(self):
        return "=====BEGIN RSA PUBLIC KEY=====\ne=%x\nd=%x\nn=%x\n=====END RSA PUBLIC KEY====="%(self.e,self.d,self.n)
