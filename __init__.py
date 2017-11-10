import common,aes,rc4,pkcs7

# Default encryption is AES-256-CTR+SHA256-HMAC
encrypt = aes.encrypt
decrypt = aes.encrypt

# Default hash is SHA56
hash = sha.sha256

# Default rng is AES-128-CTR
rand = aes.rand
