from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_keypair():
    try:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pub_bytes, priv_bytes
    except Exception as e:
        raise ValueError(f"ECDH key generation failed: {str(e)}")

def generate_shared_secret(private_key_pem, peer_public_key_pem):
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        peer_public_key = serialization.load_pem_public_key(peer_public_key_pem)
        
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_secret
    except Exception as e:
        raise ValueError(f"ECDH shared secret generation failed: {str(e)}")
