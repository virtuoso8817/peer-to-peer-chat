from Crypto.Cipher import AES
import base64
import hashlib

# Secret key (must be 16, 24, or 32 bytes)
SECRET_KEY = "your_secure_key_123"  # Change this to something strong


def get_key():
    """Generate a 32-byte key using SHA-256"""
    return hashlib.sha256(SECRET_KEY.encode()).digest()


def encrypt_message(message):
    """Encrypt message using AES"""
    key = get_key()
    cipher = AES.new(key, AES.MODE_ECB)

    # Pad message to be a multiple of 16 bytes
    pad_length = 16 - (len(message) % 16)
    message += chr(pad_length) * pad_length

    encrypted_bytes = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted_bytes).decode()


def decrypt_message(encrypted_message):
    """Decrypt message using AES"""
    key = get_key()
    cipher = AES.new(key, AES.MODE_ECB)

    decrypted_bytes = cipher.decrypt(base64.b64decode(encrypted_message))
    decrypted_message = decrypted_bytes.decode()

    # Remove padding
    pad_length = ord(decrypted_message[-1])
    return decrypted_message[:-pad_length]

