import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets

# Sample JSON data
data = {
    "message": "Hello from Python!",
    "number": 42,
    "list": [1, 2, 3]
}

def derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    # Use HKDF to derive a key from the shared secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"encryption-key",
    )
    return hkdf.derive(shared_secret)

def main():
    # Generate our private key
    private_key = X25519PrivateKey.generate()
    
    # Get our public key
    public_key = private_key.public_key()
    
    # Save our public key for Rust to use
    with open("python_key.pub", "wb") as f:
        f.write(public_key.public_bytes_raw())
    
    print("Python public key (Base64):", base64.b64encode(public_key.public_bytes_raw()).decode())
    
    # Check if Rust's public key exists
    if not os.path.exists("rust_key.pub"):
        print("\nWaiting for Rust's public key...")
        print("Please run: cargo run")
        print("Then press Enter to continue...")
        input()
    
    # Read Rust's public key
    try:
        with open("rust_key.pub", "rb") as f:
            rust_public_bytes = f.read()
            rust_public_key = X25519PublicKey.from_public_bytes(rust_public_bytes)
    except FileNotFoundError:
        print("Error: rust_key.pub not found. Please run the Rust program first.")
        return
    
    # Generate a random 24-byte salt
    salt = secrets.token_bytes(24)
    
    # Create shared secret using Diffie-Hellman
    shared_secret = private_key.exchange(rust_public_key)
    
    # Derive the encryption key using HKDF
    encryption_key = derive_key(shared_secret, salt)
    
    # Create AES-GCM cipher with the derived key
    cipher = AESGCM(encryption_key)
    
    # Generate a random 12-byte nonce
    nonce = secrets.token_bytes(12)
    
    # Convert our data to bytes
    message = json.dumps(data).encode('utf-8')
    
    # Encrypt the message
    encrypted = cipher.encrypt(nonce, message, None)
    
    # Combine salt + nonce + encrypted data
    full_message = salt + nonce + encrypted
    
    # Save the encrypted message
    with open("encrypted.bin", "wb") as f:
        f.write(full_message)
    
    print("\nData encrypted and saved to 'encrypted.bin'")
    print("Encrypted data (Base64):", base64.b64encode(full_message).decode())

if __name__ == "__main__":
    main() 