from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

def generate_keys():
    # Generate RSA key pair
    key = RSA.generate(2048)

    # Get public and private keys in PEM format
    user_pubKey = key.publickey().export_key().decode()
    user_privKey = key.export_key().decode()

    return {"public": user_pubKey, "private": user_privKey}

def generate_shared_key(user_privKey, holder_pubKey):
    # Convert keys from PEM format to RSA objects
    user_key = RSA.import_key(user_privKey.encode())
    holder_key = RSA.import_key(holder_pubKey.encode())

    # Generate a random shared key
    shared_key = get_random_bytes(16)

    # Encrypt shared key with RSA public keys
    cipher = PKCS1_OAEP.new(holder_key)
    encrypted_key = cipher.encrypt(shared_key)

    return encrypted_key.hex()  # Return encrypted key as hexadecimal string
