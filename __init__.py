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

__all__ = [
    "aes",
    "chacha20",
    "common",
    "default",
    "md4",
    "mt19937",
    "pkcs7",
    "poly1305",
    "rc4",
    "rsa",
    "sha",
    "test",
]

__version__ = '1.0.0'
__revision__ = "$Id$"
version_info = (1, 0, 0, 'final', 0)

# load everything for easy use
from mcrypto.aes import *
from mcrypto.chacha20 import *
from mcrypto.common import *
from mcrypto.default import *
from mcrypto.md4 import *
from mcrypto.mt19937 import *
from mcrypto.pkcs7 import *
from mcrypto.poly1305 import *
from mcrypto.rc4 import *
from mcrypto.rsa import *
from mcrypto.sha import *
from mcrypto.test import test_all as selftest
