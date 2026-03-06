import kyber_kem
import kdf
import aead
import ecdh

try:
    kyber_pub, kyber_sec = kyber_kem.generate_keypair()
    ecdh_pub_rec, ecdh_sec_rec = ecdh.generate_keypair()
    ecdh_pub_send, ecdh_sec_send = ecdh.generate_keypair()
    ciphertext, kyber_shared_sender = kyber_kem.encapsulate(kyber_pub)
    ecdh_shared_sender = ecdh.generate_shared_secret(ecdh_sec_send, ecdh_pub_rec)
    kyber_shared_receiver = kyber_kem.decapsulate(kyber_sec, ciphertext)
    ecdh_shared_receiver = ecdh.generate_shared_secret(ecdh_sec_rec, ecdh_pub_send)
    sender_aes_key = kdf.derive_key(ecdh_shared_sender, kyber_shared_sender)
    receiver_aes_key = kdf.derive_key(ecdh_shared_receiver, kyber_shared_receiver)
    encrypted_payload = aead.encrypt(b"SIGNAL_UNLOCK_AUTHENTICATED", sender_aes_key)
    decrypted_command = aead.decrypt(encrypted_payload, receiver_aes_key)
    print("Success")
except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"Error: {e}")
