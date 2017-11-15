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

# Module for testing all other modules

import mcrypto.aes
import mcrypto.common
import mcrypto.default
import mcrypto.md4
import mcrypto.mt19937
import mcrypto.pkcs7
import mcrypto.rc4
import mcrypto.sha
import os

# Speed up this module at the cost of revealing our secret keys
# through side channel attacks. Since these are just tests with random
# keys, this is not a problem.
mcrypto.common.ctlt = False


def test_generic_hash(alg, message, h):
    if mcrypto.common.hexstr(alg(message)) != h:
        print("Algorithm %s" % repr(alg))
        print("Message   %s" % repr(message))
        print("Expected  %s" % repr(h))
        print("Got       %s" % repr(mcrypto.common.hexstr(alg(message))))
        quit(1)


def test_aes():
    # Test primitives with null-data and null-key
    for alg, result in [(
        mcrypto.aes.aes128enc, "66:e9:4b:d4:ef:8a:2c:3b:88:4c:fa:59:ca:34:2b:2e"),
            (mcrypto.aes.aes128dec, "14:0f:0f:10:11:b5:22:3d:79:58:77:17:ff:d9:ec:3a")]:
        assert mcrypto.common.hexstr(alg("\0" * 16, "\0" * 16)) == result

    for alg, result in [(
        mcrypto.aes.aes256enc, "a7:d1:3a:59:e9:d8:75:06:d2:f7:f8:f4:ad:a2:b4:3e"),
            (mcrypto.aes.aes256dec, "32:43:65:08:ae:6e:02:d8:15:de:45:d4:91:0d:71:1b")]:
        assert mcrypto.common.hexstr(alg("\0" * 16, "\0" * 32)) == result

    # Test all mode with random data and random keys
    for key in [os.urandom(i) for i in [0, 5, 16, 32, 33]]:
        for plaintext in [os.urandom(j) for j in [0, 16, 32, 33, 1000]]:
            for enc, dec in [(
                mcrypto.aes.encrypt_128_ecb, mcrypto.aes.decrypt_128_ecb),
                (mcrypto.aes.encrypt_128_cbc,
                 mcrypto.aes.decrypt_128_cbc),
                            (mcrypto.aes.encrypt_128_ctr,
                             mcrypto.aes.decrypt_128_ctr),
                            (mcrypto.aes.encrypt_256_ecb,
                             mcrypto.aes.decrypt_256_ecb),
                            (mcrypto.aes.encrypt_256_cbc,
                             mcrypto.aes.decrypt_256_cbc),
                            (mcrypto.aes.encrypt_256_ctr, mcrypto.aes.decrypt_256_ctr), ]:
                ciphertext = enc(plaintext, key)
                assert ciphertext != plaintext
                assert dec(ciphertext, key) == plaintext


def test_default():
    # check that encryption/decryption works
    random_data = os.urandom(256)
    random_key = os.urandom(51)
    ciphertext = mcrypto.default.encrypt(random_data, random_key)
    plaintext = mcrypto.default.decrypt(ciphertext, random_key)
    assert random_data == plaintext

    for _ in range(1000):
        # check that values are in the range 0.0-1.0
        assert abs(mcrypto.default.rand() - 0.5) <= 0.5

    # check that all hashes have the same length
    hlens = [len(mcrypto.default.hash(os.urandom(ord(os.urandom(1)))))
             for _ in range(1000)]
    assert min(hlens) > 0
    assert min(hlens) == max(hlens)


def test_md4():
    for m, h in [("", "31:d6:cf:e0:d1:6a:e9:31:b7:3c:59:d7:e0:c0:89:c0"),
                 ("a", "bd:e5:2c:b3:1d:e3:3e:46:24:5e:05:fb:db:d6:fb:24"),
                 ("abc", "a4:48:01:7a:af:21:d8:52:5f:c1:0a:e8:7a:a6:72:9d"),
                 ("message digest",
                 "d9:13:0a:81:64:54:9f:e8:18:87:48:06:e1:c7:01:4b"),
                 ("abcdefghijklmnopqrstuvwxyz",
                 "d7:9e:1c:30:8a:a5:bb:cd:ee:a8:ed:63:df:41:2d:a9"),
                 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                 "04:3f:85:82:f2:41:db:35:1c:e6:27:e1:53:e7:f0:e4"),
                 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e3:3b:4d:dc:9c:38:f2:19:9c:3e:7b:16:4f:cc:05:36"), ]:
        test_generic_hash(mcrypto.md4.md4, m, h)


def test_mt19937():
    orig = mcrypto.mt19937.mt19937(ord(os.urandom(1)))
    for _ in range(1248):
        # check that all outputs are in the range 0.0-1.0
        assert abs(orig.rand() - 0.5) <= 0.5

    # check that we can clone an instance
    outputs = [orig.rand_int32() for _ in range(624)]
    clone = mcrypto.mt19937.mt19937_Clone(outputs)
    for i in range(1248):
        assert orig.rand() == clone.rand()


def test_pkcs7():
    for dlength in range(2, 100):
        for plength in range(2, 100):
            data = os.urandom(dlength)
            assert mcrypto.pkcs7.remove_padding(
                mcrypto.pkcs7.add_padding(data, plength)) == data


def test_rc4():
    r = mcrypto.rc4.rc4().rand
    for _ in range(1000):
        # check that all outputs are in the range 0.0-1.0
        assert abs(r() - 0.5) <= 0.5


def test_sha():
    for m, h in [(
        "a", "3c:2d:41:aa:92:79:b0:07:ad:e1:45:3e:12:0d:61:4a:96:b8:ad:5a"),
        ("abc",
         "ff:c3:60:30:cd:40:5c:2d:fd:8b:e8:ab:34:e4:de:d3:5c:03:4a:f8"),
                ("message digest",
                 "9c:09:be:b6:b8:41:f7:42:6c:87:af:4d:47:b8:9f:69:af:4a:59:63"),
                ("abcdefghijklmnopqrstuvwxyz",
                 "d2:31:b3:ca:7a:f9:f7:fa:f6:33:84:50:7d:4c:1f:b0:71:00:03:0e"),
                ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                 "43:6b:f6:9b:c9:79:e0:e3:71:5e:a6:c0:7d:dd:06:e2:1e:0e:02:66"),
                ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "33:6f:15:39:0e:38:d4:6c:76:fd:c3:06:15:47:0c:77:62:bd:f5:7b"), ]:
        test_generic_hash(mcrypto.sha.sha1, m, h)

    for m, h in [(
        "", "e3:b0:c4:42:98:fc:1c:14:9a:fb:f4:c8:99:6f:b9:24:27:ae:41:e4:64:9b:93:4c:a4:95:99:1b:78:52:b8:55"),
        ("a",
         "08:87:5e:3d:41:31:4b:d1:dc:2b:2d:b5:e4:f4:dd:04:6b:f3:ec:27:99:40:34:57:ae:6e:9f:4e:9d:39:34:22"),
                ("abc",
                 "20:3b:1d:90:16:06:08:02:fe:5e:f8:04:36:61:11:59:de:18:68:b5:8d:44:94:0e:3d:39:79:ea:b5:f4:d1:93"),
                ("message digest",
                 "ae:cd:a3:d8:0b:a1:87:cd:6b:8e:4d:ab:62:4f:b7:02:1d:78:f3:3e:ef:fa:04:e0:b9:96:98:f9:15:98:73:f9"),
                ("abcdefghijklmnopqrstuvwxyz",
                 "2a:fe:1f:49:2b:4c:d7:0c:86:63:a3:0b:34:39:a4:62:d2:f6:52:8b:4e:ee:2a:a4:11:1a:3e:cb:b6:6e:eb:98"),
                ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                 "90:97:02:a2:ce:48:18:c4:22:70:f3:5d:2d:2d:05:2d:cc:e8:63:82:ab:d1:f1:8d:3f:37:43:5d:b2:b6:85:1e"),
                ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "1c:8e:a2:34:70:bb:48:91:e4:a9:c9:a5:77:15:0c:a7:4e:f4:0d:e5:02:d4:e9:43:79:48:e3:0f:10:02:14:fb"), ]:
        test_generic_hash(mcrypto.sha.sha256, m, h)


def test_all():
    test_aes()
    test_default()
    test_md4()
    test_mt19937()
    test_pkcs7()
    test_rc4()
    test_sha()
