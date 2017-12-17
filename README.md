# crypturd

Implementation of several cryptographic primitives. I created this
library to to test specific attacks on existing cryptograpy.

Performance is not a priority and I make no effort from prevented
anyone from using the wrong schemes. My only goals here are to make
correct implementations which are easy to use.

# Example usage

    #!/usr/bin/env python2
    import crypturd

    message = "Attack at dawn!"       # can be any length, even empty
    key = "yKj3xBCBatVG1Q0gZ8ss2xbC4" # can be any length, >128 bits of entropy is recommended

    # Default encryption is ChaCha20+Poly1305
    ciphertext = crypturd.encrypt(message,key)

    print crypturd.decrypt(ciphertext,key)


# Symmetric key crypto

- AES (128/256 bit variant in ECB,CBC or CTR) (Vulnerable to timing attacks)
- ChaCha20
- RC4 (Weak cipher)

# Public key crypto

- RSA (3072-bit, slow, vulnerable to chosen ciphertext attacks)
- DSA
- Hash-based signatures (Custom scheme for many-time usage with only 8.84 KB signatures)

# Hash algorithms

- MD4 (Insecure)
- SHA1 (Insecure)
- SHA256

# Message authentication codes

- Poly1305
- Sha256-HMAC
- CBC-MAC (insecure)

# Random number generators

- AES-128-CTR (custom)
- Chacha20 (custom)
- RC4 (Insecure)
- MT19937 (Insecure)

# Padding schemes

- Null Padding
- PKCS7

# Security

This is a single man project, nobody except the author has reviewed
this code.

USE AT YOUR OWN RISK

Based on input/output all primitives are implemented correctly.
However this does not necessarily exclude the possibility of
side-channel attacks.

Some primitives included in this library easily broken, do not use
them for anything you care about. The default hash function, random
number generator and symmetric key cipher are chosen to be secure. If
in doubt, use the defaults (as specified in default.py).

# Side channel attacks

The current AES implementation can leak its internal state due to
timing differences in lookup tables between recently and non-recently
accessed values.

ChaCha20 is immune to side-channel attack when implemented correctly.
On 64-bit machines the ChaCha20 in this library is not vulnerable to
side-channel attacks. However on 32-bit cpu python may treat number
in the range 2^31 - 2^32 as bignums, allowing for side-channel attacks.

# Technical notes

Due to differences in string formatting in python2 and python3, this
library only work with python2.

Error messages are hidden by default to prevent leakage of data. To
get accurate exception handling add the following line to your code.

    crypturd.common.DEBUG = True

# Key derivation

For easy use all cipher can be used with arbitrary size user keys that
are converted to appropriately sized keys

- Keys that are shorter than expected are padded with null bytes
- Strings of the correct size are use exactly
- hex formated string of the correct size are used exactly
- Otherwise, the input string is hashed using sha256 (and truncated for 128-bit keys)

The following keys are all treated as if they were identical

- "yellow submarine"
- "yellow submarine\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
- "79656c6c6f77207375626d6172696e6500000000000000000000000000000000"

# Nonce generation

The generation of nonces in this library relies on os.urandom(). On
common Gnu/Linux distribution (Debian/Ubuntu/Red Hat/Gentoo/Arch/SuSe
etc) and BSD systems (OpenBSD,FreeBSD) I can confirm that this
functionality is implemented correctly.

On other popular systems (Microsoft Windows, Apple Mac OS and other
proprietary systems), I cannot assure that nonces are generated
securely.

# Ciphertext structure

The general structure of all authenticated ciphers is as follows

    (IV or nonce) || (Ciphertext) || MAC

For Chacha20 the format is

    96-bit nonce (for both ciphertext and MAC) || Ciphertext || Poly1305 MAC (128 bits)

For most modes AES the format is

    128-bit IV (for ciphertext) || Ciphertext || SHA256-MAC (256 bits)

AES-128-ECB and AES-256-ECB do not use Initialization vectors or
message authentication codes.

Plaintexts in AES-ECB and AES-CBC are padded using PKCS7.

