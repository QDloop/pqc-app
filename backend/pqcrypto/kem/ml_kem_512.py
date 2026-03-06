import os

def generate_keypair():
    """Simulates generating a Kyber 512 keypair."""
    public_key = os.urandom(800)
    secret_key = os.urandom(1632)
    return public_key, secret_key

def encrypt(public_key):
    """Simulates Kyber 512 encapsulation."""
    import hashlib
    ciphertext = os.urandom(768)
    shared_secret = hashlib.sha256(ciphertext).digest()
    return ciphertext, shared_secret

def decrypt(secret_key, ciphertext):
    """Simulates Kyber 512 decapsulation. In a real scenario, this involves lattice math."""
    # Since this is a mock without real math, we'll return a deterministic hash of the ciphertext 
    # to emulate "recovering" the shared secret for testing.
    import hashlib
    # We take the sha256 of the ciphertext to simulate recovering the securely wrapped secret
    # If the app needed exact matching round-trips, the encrypt logic would need to share state.
    # We will just return 32 bytes.
    return hashlib.sha256(ciphertext).digest()
