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

def add_padding(s,n):
    "Pad input to a multiple of n bytes"
    if n<1:
        raise Exception("Invalid padding length")
    pad_length = n-(len(s)%n)
    if pad_length > 255:
        raise Exception("Invalid padding length")
    elif pad_length==0:
        pad_length = n
    return s + chr(pad_length)*pad_length

def remove_padding(s):
    pad_length = ord(s[-1])
    for i in range(pad_length):
        if ord(s[-1-i]) != pad_length:
            raise Exception("Invalid padding")
    return s[:-pad_length]
