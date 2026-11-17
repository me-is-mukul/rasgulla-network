import os
import base64
import struct
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timezone, timedelta


# ------------------------------------------------------------
# Timezone Setup (IST)
# ------------------------------------------------------------
IST = timezone(timedelta(hours=5, minutes=30))


# ============================================================
# SHA-256 HASH FOR FILE INTEGRITY
# ============================================================
def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# ============================================================
# KEY DERIVATION — PBKDF2 (HMAC-SHA256, 200k iterations)
# ============================================================
def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password.encode(), salt, dkLen=32, count=200000)


# ============================================================
# TEXT ENCRYPTION (Used by text_routes.py)
# ============================================================
def encrypt_text(plaintext: str, key: bytes):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return ciphertext, iv


# ============================================================
# TEXT DECRYPTION (Used by text_routes.py)
# ============================================================
def decrypt_text(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode("utf-8")


# ============================================================
# FILE ENCRYPTION WITH TIME-LOCK (AES-256-CBC)
#
# Purpose of FIX:
#  - HTML provides IST time (local)
#  - Convert IST → UTC before saving
# ============================================================
def encrypt_file(input_path, output_path, key, salt, unlock_time=None):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    with open(input_path, "rb") as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # --------------------------------------------------------
    # Time-lock logic FIXED properly
    # --------------------------------------------------------
    if unlock_time:
        # Attach IST timezone to user-selected datetime
        unlock_time = unlock_time.replace(tzinfo=IST)

        # Convert IST → UTC (absolute timestamp)
        unix_time = int(unlock_time.astimezone(timezone.utc).timestamp())
    else:
        unix_time = 0  # no lock

    # Write encrypted file structure
    with open(output_path, "wb") as f:
        f.write(salt)                           # 16 bytes
        f.write(iv)                             # 16 bytes
        f.write(struct.pack(">Q", unix_time))   # 8 bytes timestamp (UTC)
        f.write(ciphertext)


# ============================================================
# FILE DECRYPTION (Time-Lock Enforced)
#
# FIX:
#  - Compare UTC now vs stored UTC timestamp
#  - Display unlock time in IST to user
# ============================================================
def decrypt_file(input_path, output_path, key):
    with open(input_path, "rb") as f:
        salt = f.read(16)
        iv = f.read(16)
        unlock_bytes = f.read(8)
        ciphertext = f.read()

    unlock_ts = struct.unpack(">Q", unlock_bytes)[0]

    # --------------------------------------------------------
    # FIXED: Compare current time in UTC properly
    # --------------------------------------------------------
    now = datetime.now(timezone.utc).timestamp()

    if unlock_ts != 0 and now < unlock_ts:
        # Convert stored UTC timestamp → IST for display
        unlock_dt = datetime.fromtimestamp(unlock_ts, tz=IST)
        raise ValueError(
            f"File is locked until {unlock_dt.strftime('%Y-%m-%d %H:%M:%S')} IST"
        )

    # Proceed with decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(output_path, "wb") as f:
        f.write(plaintext)
