import pqcrypto.kem.ml_kem_512 as ml_kem_512

def generate_keypair():
    """
    Generates a Kyber (ML-KEM-512) public and secret keypair.
    """
    try:
        return ml_kem_512.generate_keypair()
    except Exception as e:
        raise ValueError(f"Kyber key generation failed: {str(e)}")

def encapsulate(public_key):
    """
    Encapsulates a shared secret against the provided public key.
    """
    try:
        return ml_kem_512.encrypt(public_key)
    except Exception as e:
        raise ValueError(f"Kyber encapsulation failed: {str(e)}")

def decapsulate(secret_key, ciphertext):
    """
    Decapsulates the ciphertext using the secret key to recover the shared secret.
    """
    try:
        return ml_kem_512.decrypt(secret_key, ciphertext)
    except Exception as e:
        raise ValueError(f"Kyber decapsulation failed: {str(e)}")
