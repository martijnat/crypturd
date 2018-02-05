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

# Default encryption is ChaCha20 (with poly1305 mac)
encrypt = crypturd.chacha20.chacha20_encrypt
decrypt = crypturd.chacha20.chacha20_decrypt

# Default hash is SHA56
hash = crypturd.sha.sha256

# Default rng is based of ChaCha20
rand = crypturd.chacha20.rand

# Default signature scheme is my custom hash-based scheme
sign_keypair = crypturd.manytimessig.key_pair
verify = crypturd.manytimessig.verify
sign = crypturd.manytimessig.sign

# Default Key exchange algorithm is ECDH (over Ed25519)
DH_keypair = crypturd.ecc.ECDH_public_private_keypair
DH_common_secret =  crypturd.ecc.ECDH_calculate_common_secret
