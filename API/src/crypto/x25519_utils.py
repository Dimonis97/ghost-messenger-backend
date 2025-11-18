
from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random as nacl_random
import hashlib


def generate_x25519_keypair():
    """
    Генерирует пару ключей X25519 для ECDH.
    Возвращает (private_key, public_key).
    """
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key


def derive_shared_secret(priv: PrivateKey, peer_pub: bytes):
    """
    Получение общего секрета через X25519.
    Возвращает 32-байтовый shared_secret.
    """
    peer_public_key = PublicKey(peer_pub)
    box = Box(priv, peer_public_key)
    return box.shared_key()


def kdf_sha256(shared_secret: bytes) -> bytes:
    """
    Простой KDF чтобы получить AES-ключ длиной 256 бит.
    """
    return hashlib.sha256(shared_secret).digest()


def generate_nonce():
    """
    Генерирует криптографически безопасный nonce для AES-GCM.
    """
    return nacl_random(12)
