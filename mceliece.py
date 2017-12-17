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
from crypturd.common import Matrix,RandomBinaryNonSingularMatrix,RandomPermutationMatrix,IdentityMatrix

# Initial prototype, offers absolutely no security

class PrivateKey():
    def __init__(self, n = 6960, k = 5413, t = 119):
        self.n = 32
        self.k = self.n
        self.t = 0
        self.S = RandomBinaryNonSingularMatrix(self.k)
        self.G = IdentityMatrix(self.n) # TODO: Change this to a k x n binary goppa code
        self.P = RandomPermutationMatrix(self.n)

    def PublicKey(self):
        G_hat = (self.S*self.G*self.P)%2
        return McEliecePublicKey(G_hat,self.t)

    def decrypt(self,c):
        Pi = self.P.BinaryInverse()
        Si = self.S.BinaryInverse()
        C = self.G.BinaryInverse()
        c_ = (c*Pi)%2
        m_ = c_
        m = (m_*Si)%2
        x = sum([m[0][i]<<(i) for i in range(m.width)])
        return crypturd.int2bigendian(x)



class McEliecePublicKey():
    def __init__(self,G_hat,t):
        self.G_hat = G_hat
        self.t = t

    def encrypt(self,msg):
        M = crypturd.common.bigendian2int(msg)
        x = Matrix(1,self.G_hat.width,[1&(M>>i) for i in range(self.G_hat.width)])
        c_ = (x*self.G_hat)%2
        e = [0 for i in range(self.G_hat.width)]
        while sum(e)<self.t:
            e[crypturd.random_mod(len(e))] = 1
        return (c_ + Matrix(1,self.G_hat.height,e))%2

