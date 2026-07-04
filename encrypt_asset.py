import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

def encrypt_file(input_path: str, output_path: str, passphrase: str):
    nonce = os.urandom(12)
    salt = os.urandom(16)
    
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=3,
        lanes=1,
        memory_cost=262144
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    
    with open(input_path, 'rb') as f:
        plaintext = f.read()
        
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext, None)
    
    with open(output_path, 'wb') as f:
        f.write(nonce)
        f.write(salt)
        f.write(ciphertext)
        
    print(f"Encryption successful: {output_path}")
    print(f"Packaged Format: [Nonce (12)] + [Salt (16)] + [Data ({len(ciphertext)})]")

if __name__ == "__main__":
    secret_passphrase = "42636"
    
    input_file = "sample.jpg"
    output_file = "sample.enc"
    
    if not os.path.exists(input_file):
        with open(input_file, 'wb') as f:
            f.write(b"CryptStream dummy payload content.")
            
    encrypt_file(input_file, output_file, secret_passphrase)