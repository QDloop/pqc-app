from Crypto.Cipher import AES
import os
import base64

def encrypt(message: bytes, key: bytes) -> dict:
    """
    Encrypts a message using AES-GCM for Authenticated Encryption with Associated Data (AEAD).
    Returns Base64 encoded payload to ensure no raw bytes are serialized.
    """
    try:
        nonce = os.urandom(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if isinstance(message, str):
            message = message.encode('utf-8')
        ciphertext, tag = cipher.encrypt_and_digest(message)
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8')
        }
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt(encrypted_data: dict, key: bytes) -> bytes:
    """
    Decrypts and verifies the ciphertext securely. Protects against invalid/tampered ciphertext.
    """
    try:
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        tag = base64.b64decode(encrypted_data["tag"])
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        raise ValueError("Invalid ciphertext or decryption failed securely.")
