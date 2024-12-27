import pytest
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from atoma_sdk.encryption import (
    encrypt_request,
    decrypt_response,
    EncryptedData,
    hash_plaintext,
    derive_key
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

def test_encryption_decryption_flow():
    """Test the complete encryption/decryption flow without external API calls"""
    # Create test data
    plaintext = {
        "messages": [
            {"role": "user", "content": "Hello!"}
        ],
        "model": "test-model",
        "temperature": 0.7
    }
    
    # Generate a test node key pair (simulating the node's key)
    node_private_key = X25519PrivateKey.generate()
    node_public_key = node_private_key.public_key()
    node_public_bytes = node_public_key.public_bytes_raw()
    
    # Encrypt the request
    encrypted_data = encrypt_request(plaintext, node_public_bytes)
    
    # Verify encrypted data format
    assert isinstance(encrypted_data.ciphertext, str)
    assert isinstance(encrypted_data.salt, str)
    assert isinstance(encrypted_data.nonce, str)
    assert isinstance(encrypted_data.client_dh_public_key, str)
    assert isinstance(encrypted_data.plaintext_body_hash, str)
    
    # Verify all fields are base64 encoded
    assert base64.b64decode(encrypted_data.ciphertext)
    assert base64.b64decode(encrypted_data.salt)
    assert base64.b64decode(encrypted_data.nonce)
    assert base64.b64decode(encrypted_data.client_dh_public_key)
    assert base64.b64decode(encrypted_data.plaintext_body_hash)
    
    # Create response data
    response_data = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Hi there!"
                }
            }
        ],
        "model": "test-model"
    }
    
    # Create encrypted response (simulating what the node would do)
    # First, encrypt the response data using the client's public key
    client_public_key = X25519PublicKey.from_public_bytes(base64.b64decode(encrypted_data.client_dh_public_key))
    
    # Generate shared secret (from node's perspective)
    shared_secret = node_private_key.exchange(client_public_key)
    
    # Derive encryption key
    salt = base64.b64decode(encrypted_data.salt)
    encryption_key = derive_key(shared_secret, salt)
    
    # Create cipher
    cipher = AESGCM(encryption_key)
    
    # Convert response data to JSON bytes
    response_json = json.dumps(response_data)
    response_bytes = response_json.encode()
    
    # Encrypt response
    nonce = base64.b64decode(encrypted_data.nonce)
    response_ciphertext = cipher.encrypt(nonce, response_bytes, None)
    
    # Hash response plaintext
    response_hash = hash_plaintext(response_json)
    
    # Create encrypted response
    encrypted_response = EncryptedData(
        ciphertext=base64.b64encode(response_ciphertext).decode(),
        salt=encrypted_data.salt,  # Reuse the same salt
        nonce=encrypted_data.nonce,  # Reuse the same nonce
        client_dh_public_key=encrypted_data.client_dh_public_key,
        plaintext_body_hash=response_hash,
        node_dh_public_key=base64.b64encode(node_public_bytes).decode()
    )
    
    # Get the private key from the encryption process
    client_private_key = encrypted_data.private_key
    
    # Decrypt the response
    decrypted_data = decrypt_response(encrypted_response, client_private_key)
    
    # Verify decrypted data matches original response data
    assert isinstance(decrypted_data, dict)
    assert "choices" in decrypted_data
    assert len(decrypted_data["choices"]) == 1
    assert decrypted_data["choices"][0]["message"]["role"] == "assistant"
    assert decrypted_data["choices"][0]["message"]["content"] == "Hi there!"
    assert decrypted_data["model"] == "test-model"

def test_hash_plaintext():
    """Test the plaintext hashing function"""
    test_data = {"test": "data"}
    hash1 = hash_plaintext('{"test":"data"}')  # Use exact JSON string
    hash2 = hash_plaintext('{"test":"data"}')  # Same JSON string
    hash3 = hash_plaintext('{"different":"data"}')
    
    # Same input should produce same hash
    assert hash1 == hash2
    # Different input should produce different hash
    assert hash1 != hash3
    # Hash should be base64 encoded
    assert base64.b64decode(hash1)

def test_derive_key():
    """Test the key derivation function"""
    # Test with fixed inputs for deterministic testing
    shared_secret = b"test_shared_secret" * 2  # 32 bytes
    salt = b"test_salt" * 2  # 16 bytes
    
    key1 = derive_key(shared_secret, salt)
    key2 = derive_key(shared_secret, salt)
    key3 = derive_key(shared_secret, b"different_salt" * 2)
    
    # Same input should produce same key
    assert key1 == key2
    # Different salt should produce different key
    assert key1 != key3
    # Key should be 32 bytes (256 bits)
    assert len(key1) == 32

def test_encryption_with_invalid_data():
    """Test encryption with invalid data to ensure proper error handling"""
    with pytest.raises(Exception):
        # Try to encrypt with invalid node public key
        encrypt_request({"test": "data"}, b"invalid_key")
    
    with pytest.raises(ValueError):
        # Try to decrypt with mismatched hash
        encrypted_data = EncryptedData(
            ciphertext="invalid",
            salt="invalid",
            nonce="invalid",
            client_dh_public_key="invalid",
            plaintext_body_hash="invalid",
            node_dh_public_key="invalid"
        )
        decrypt_response(encrypted_data, X25519PrivateKey.generate()) 