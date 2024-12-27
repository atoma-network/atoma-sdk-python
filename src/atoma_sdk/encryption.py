import json
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets
from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class EncryptedData:
    ciphertext: str  # base64 encoded
    salt: str  # base64 encoded
    nonce: str  # base64 encoded
    client_dh_public_key: str  # base64 encoded
    plaintext_body_hash: str  # base64 encoded
    node_dh_public_key: Optional[str] = None  # base64 encoded, only in response
    private_key: Optional[X25519PrivateKey] = None  # only used for testing

def derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"encryption-key",
    )
    return hkdf.derive(shared_secret)

def hash_plaintext(plaintext: str) -> str:
    """Hash the plaintext using SHA-256 and return base64 encoded string"""
    h = hashlib.sha256()
    h.update(plaintext.encode())
    return base64.b64encode(h.digest()).decode()

def encrypt_request(plaintext: Dict[str, Any], node_public_key: bytes) -> EncryptedData:
    """Encrypt a request for confidential compute"""
    # Generate our private key
    private_key = X25519PrivateKey.generate()
    client_public_key = private_key.public_key()
    
    # Convert node public key from bytes to X25519PublicKey
    node_public_key_obj = X25519PublicKey.from_public_bytes(node_public_key)
    
    # Generate shared secret
    shared_secret = private_key.exchange(node_public_key_obj)
    
    # Generate salt and nonce
    salt = secrets.token_bytes(24)
    nonce = secrets.token_bytes(12)
    
    # Derive encryption key
    encryption_key = derive_key(shared_secret, salt)
    
    # Create cipher
    cipher = AESGCM(encryption_key)
    
    # Convert plaintext to JSON bytes
    plaintext_json = json.dumps(plaintext)
    plaintext_bytes = plaintext_json.encode()
    
    # Encrypt
    ciphertext = cipher.encrypt(nonce, plaintext_bytes, None)
    
    # Hash plaintext
    plaintext_hash = hash_plaintext(plaintext_json)
    
    return EncryptedData(
        ciphertext=base64.b64encode(ciphertext).decode(),
        salt=base64.b64encode(salt).decode(),
        nonce=base64.b64encode(nonce).decode(),
        client_dh_public_key=base64.b64encode(client_public_key.public_bytes_raw()).decode(),
        plaintext_body_hash=plaintext_hash,
        private_key=private_key  # Store for testing
    )

def decrypt_response(encrypted_data: EncryptedData, private_key: X25519PrivateKey) -> Dict[str, Any]:
    """Decrypt a response from confidential compute"""
    # Decode all base64 fields
    ciphertext = base64.b64decode(encrypted_data.ciphertext)
    salt = base64.b64decode(encrypted_data.salt)
    nonce = base64.b64decode(encrypted_data.nonce)
    node_public_key = base64.b64decode(encrypted_data.node_dh_public_key)
    
    # Convert node public key from bytes to X25519PublicKey
    node_public_key_obj = X25519PublicKey.from_public_bytes(node_public_key)
    
    # Generate shared secret
    shared_secret = private_key.exchange(node_public_key_obj)
    
    # Derive encryption key
    encryption_key = derive_key(shared_secret, salt)
    
    # Create cipher
    cipher = AESGCM(encryption_key)
    
    # Decrypt
    plaintext_bytes = cipher.decrypt(nonce, ciphertext, None)
    
    # Parse JSON
    plaintext = json.loads(plaintext_bytes.decode())
    
    # Verify hash
    computed_hash = hash_plaintext(json.dumps(plaintext))
    if computed_hash != encrypted_data.plaintext_body_hash:
        raise ValueError("Plaintext hash mismatch")
    
    return plaintext 