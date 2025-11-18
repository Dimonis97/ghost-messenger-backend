def save_message(session_id: bytes, data: bytes):
    with open("messages.log", "ab") as f:
        f.write(session_id + b" | " + data + b"\n")

