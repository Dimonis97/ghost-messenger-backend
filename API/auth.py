import os
from src.crypto.x25519_utils import (
    generate_x25519_keypair,
    derive_shared_secret,
    kdf_sha256
)

SESSIONS = {}


async def handle_auth(reader, writer):
    """
    Клиент присылает:
    1) public_key (32 байта)
    
    Сервер отвечает:
    1) session_id (8 байт)
    2) server_pubkey (32 байта)
    """

    client_pub = await reader.read(32)

    server_priv, server_pub = generate_x25519_keypair()

    shared = derive_shared_secret(server_priv, client_pub)
    aes_key = kdf_sha256(shared)

    session_id = os.urandom(8)

    SESSIONS[session_id] = {
        "aes_key": aes_key,
        "client_pub": client_pub
    }

    writer.write(session_id + bytes(server_pub))
    await writer.drain()

