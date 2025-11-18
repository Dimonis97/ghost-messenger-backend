from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: bytes = b""):
    aes = AESGCM(key)
    nonce = AESGCM.generate_key(bit_length=96)[:12]  # 12 байт
    ciphertext = aes.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b""):
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, aad)

