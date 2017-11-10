import common,aes,rc4,pkcs7

# Default encryption is AES-256-CTR+SHA256-HMAC
encrypt = aes.encrypt
decrypt = aes.encrypt

# Default hash is SHA56
hash = sha.sha256

# Default rng is RC4 (Placeholder untile a secure rng is implemented)
# TODO: implement csrng
rand = rc4.rc4().rand
