# USE AT YOUR OWN RISK

I make no guarantees towards the safe implementation of these
algorithms.

# mcrypto

Implementation of several cryptographic primitives.

# Example usage

    from mcrypto.default import encrypt
    # default encryption method is aes-256-ctr+sha25-hmac

    plaintext = "Attack at dawn"
    key = "Random password."
    ciphertext = encrypt(plaintext,key)

# Technical notes

This implementation **only** works correctly with python2. Python3
will fail because of differences in string encoding. PyPy will
technically work but introduce side-channel attacks during table
lookups.

# Block ciphers

- AES (128/256 bit) (ECB/CBC/CTR) (SHA256-HMAC)
- ChaCha20

# Hash algorithms

- MD4
- SHA1
- SHA256

# Random number generators

- AES-128-CTR
- RC4
- MT19937

# Padding schemes

- Null Padding
- PKCS7


