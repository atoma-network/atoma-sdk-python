from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import secrets
import base64

from atoma_sdk.models.confidentialchatcompletionrequest import ConfidentialChatCompletionRequest
from atoma_sdk.models.confidentialchatcompletionresponse import ConfidentialChatCompletionResponse          # random salt, base64 encoded

def derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"encryption-key",
        )
        return hkdf.derive(shared_secret)
    except Exception as e:
        raise ValueError(f"Failed to derive encryption key: {str(e)}") from e

def calculate_hash(data: bytes) -> bytes:
    try:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()
    except Exception as e:
        raise ValueError(f"Failed to calculate hash: {str(e)}") from e
def encrypt_message(sdk, private_key: X25519PrivateKey, chat_completions_request_body: BaseModel, model: str) -> ConfidentialChatCompletionRequest:
    # Generate our private key
    try:
        public_key = private_key.public_key()
    except Exception as e:
        raise ValueError(f"Failed to generate key pair: {str(e)}") from e
    
    # Get node's public key
    try:
        res = sdk.confidential_node_public_key_selection.select_node_public_key(model_name=model)
        if not res or not res.public_key:
            raise ValueError("Failed to retrieve node public key")
        public_key_node = res.public_key
        stack_small_id = res.stack_small_id
    except Exception as e:
        raise ValueError(f"Failed to get node public key: {str(e)}") from e

    # Generate a random salt and create shared secret
    try:
        salt = secrets.token_bytes(24)
        shared_secret = private_key.exchange(public_key_node)
        encryption_key = derive_key(shared_secret, salt)
        cipher = AESGCM(encryption_key)
        nonce = secrets.token_bytes(12)
    except Exception as e:
        raise ValueError(f"Failed to setup encryption: {str(e)}") from e
    
    # Encrypt the message
    try:
        message = chat_completions_request_body.model_dump_json().encode('utf-8')
        plaintext_body_hash = calculate_hash(message)
        ciphertext = cipher.encrypt(nonce, message, None)
        
        # Convert binary data to base64 strings
        return ConfidentialChatCompletionRequest(
            ciphertext=base64.b64encode(ciphertext).decode('utf-8'),
            client_dh_public_key=base64.b64encode(public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode('utf-8'),
            nonce=base64.b64encode(nonce).decode('utf-8'),
            plaintext_body_hash=base64.b64encode(plaintext_body_hash).decode('utf-8'),
            salt=base64.b64encode(salt).decode('utf-8'),
            stack_small_id=stack_small_id,
            stream=chat_completions_request_body.stream,
            max_tokens=chat_completions_request_body.max_tokens
        )
    except Exception as e:
        raise ValueError(f"Failed to encrypt message: {str(e)}") from e

def decrypt_message(private_key: X25519PrivateKey, encrypted_message: ConfidentialChatCompletionResponse) -> bytes:
    try:
        # Decode base64 values
        ciphertext = base64.b64decode(encrypted_message.ciphertext)
        node_public_key = X25519PublicKey.from_public_bytes(base64.b64decode(encrypted_message.node_dh_public_key))
        nonce = base64.b64decode(encrypted_message.nonce)
        salt = base64.b64decode(encrypted_message.salt)
        expected_hash = base64.b64decode(encrypted_message.plaintext_body_hash)
        
        # Load node's public key and create shared secret
        shared_secret = private_key.exchange(node_public_key)
        
        # Derive encryption key
        encryption_key = derive_key(shared_secret, salt)
        cipher = AESGCM(encryption_key)
        
        # Decrypt the message
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        
        # Verify hash
        actual_hash = calculate_hash(plaintext)
        if not secrets.compare_digest(actual_hash, expected_hash):
            raise ValueError("Message hash verification failed")
            
        return plaintext
        
    except Exception as e:
        raise ValueError(f"Failed to decrypt message: {str(e)}") from e
