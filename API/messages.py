from src.crypto.aes_gcm import decrypt_aes_gcm
from src.api.auth import SESSIONS


async def handle_messages(reader, writer):
    """
    Формат:
    8 байт   → session_id
    12 байт  → nonce
    2 байта  → длина ciphertext
    n байт   → ciphertext
    """

    session_id = await reader.read(8)

    if session_id not in SESSIONS:
        writer.write(b"ERR_NO_SESSION")
        await writer.drain()
        return

    aes_key = SESSIONS[session_id]["aes_key"]

    nonce = await reader.read(12)

    length_bytes = await reader.read(2)
    length = int.from_bytes(length_bytes, "big")

    ciphertext = await reader.read(length)

    try:
        plaintext = decrypt_aes_gcm(aes_key, nonce, ciphertext)
        print("Message:", plaintext)

        writer.write(b"OK")
        await writer.drain()

    except Exception:
        writer.write(b"ERR_DECRYPT")
        await writer.drain()

