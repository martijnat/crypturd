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


# This file sets up default values for

import mcrypto.common
import mcrypto.aes
import mcrypto.rc4
import mcrypto.pkcs7

# Default encryption is chacha20 (with poly1305 mac)
encrypt = mcrypto.chacha20.chacha20_encrypt
decrypt = mcrypto.chacha20.chacha20_decrypt

# Default hash is SHA56
hash = mcrypto.sha.sha256

# Default rng is AES-128-CTR
rand = mcrypto.chacha20.rand
