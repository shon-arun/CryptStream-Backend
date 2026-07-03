import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt_image():
    input_filename = "sample.jpg"
    output_filename = "sample.enc"
    
    # 1. 256-bit Hardcoded AES Key (Must be exactly 32 bytes)
    # Ensure this identical key is used later in your Flutter app for decryption!
    AES_KEY = b"MySecret32ByteHardcodedKeyHere42" 
    
    if len(AES_KEY) != 32:
        raise ValueError("AES key must be exactly 32 bytes long for AES-256.")


    print(f"Reading {input_filename}...")
    with open(input_filename, "rb") as f:
        raw_data = f.read()

    # 2. Apply PKCS7 Padding to make the data a multiple of the AES block size (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(raw_data) + padder.finalize()

    # 3. Generate a random 16-byte Initialization Vector (IV)
    iv = os.urandom(16)

    # 4. Initialize AES-256-CBC Cipher
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # 5. Save Ciphertext to file
    # CRITICAL: Prepend the 16-byte IV to the file so the Flutter app knows what IV to use!
    print(f"Writing encrypted bytes to {output_filename}...")
    with open(output_filename, "wb") as f:
        f.write(iv + ciphertext)

    return # Add deletion feature later after testing. ## Better enabled ASAP
    # 6. Securely delete the raw image asset
    print(f"Securely deleting the raw asset '{input_filename}'...")
    # Overwrite file with random bytes before unlinking to prevent data recovery on standard disks
    file_size = os.path.getsize(input_filename)
    with open(input_filename, "wb") as f:
        f.write(os.urandom(file_size))
    os.remove(input_filename)
    print("Asset successfully encrypted and raw file completely removed.")

if __name__ == "__main__":
    encrypt_image()