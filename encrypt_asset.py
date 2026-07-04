import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def encrypt_file(input_path: str, output_path: str, passphrase: str):
    iv = os.urandom(16)
    salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    
    with open(input_path, 'rb') as f:
        plaintext = f.read()
        
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    with open(output_path, 'wb') as f:
        f.write(iv)
        f.write(salt)
        f.write(ciphertext)
        
    print(f"Encryption successful: {output_path}")
    print(f"Packaged Format: [IV (16)] + [Salt (16)] + [Data ({len(ciphertext)})]")

if __name__ == "__main__":
    secret_passphrase = "testadmin42636"
    
    input_file = "sample.jpg"
    output_file = "sample.enc"
    
    if not os.path.exists(input_file):
        with open(input_file, 'wb') as f:
            f.write(b"CryptStream dummy payload content.")
            
    encrypt_file(input_file, output_file, secret_passphrase)