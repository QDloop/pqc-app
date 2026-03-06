from Crypto.Hash import SHA3_256

def derive_key(ecdh_secret: bytes, kyber_secret: bytes) -> bytes:
    """
    Derives a symmetric AES key using NIST-standard SHA3-256 KDF.
    Hybrid implementation: FinalKey = SHA3(ECDH_secret || Kyber_secret)
    """
    if isinstance(ecdh_secret, str):
        ecdh_secret = ecdh_secret.encode('utf-8')
    if isinstance(kyber_secret, str):
        kyber_secret = kyber_secret.encode('utf-8')
        
    combo = ecdh_secret + kyber_secret
    
    hash_obj = SHA3_256.new()
    hash_obj.update(combo)
    return hash_obj.digest()
