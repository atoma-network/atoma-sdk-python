from pydantic import BaseModel
from .basesdk import BaseSDK
from atoma_sdk import models, utils
from atoma_sdk._hooks import HookContext
from atoma_sdk.types import OptionalNullable, UNSET
from atoma_sdk.utils import eventstreaming, get_security_from_env
from typing import Any, Dict, List, Mapping, Optional, Union, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets
import base64


class EncryptedMessage(BaseModel):
    ciphertext: str             # request body encrypted with node's public key, base64 encoded
    client_dh_public_key: str   # our public key, base64 encoded
    nonce: str                  # random nonce, base64 encoded
    plaintext_body_hash: str    # hash of the request body, base64 encoded
    salt: str                   # random salt, base64 encoded

class DecryptedMessage(BaseModel):
    ciphertext: str             # request body encrypted with node's public key, base64 encoded
    node_dh_public_key: str     # node's public key, base64 encoded
    nonce: str                  # random nonce, base64 encoded
    plaintext_body_hash: str    # hash of the request body, base64 encoded
    salt: str                   # random salt, base64 encoded

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
        raise ValueError(f"Failed to derive encryption key: {str(e)}")

def calculate_hash(data: bytes) -> bytes:
    try:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()
    except Exception as e:
        raise ValueError(f"Failed to calculate hash: {str(e)}")

def encrypt_message(sdk: BaseSDK, chat_completions_request_body: BaseModel, model: str) -> EncryptedMessage:
    # Generate our private key
    try:
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
    except Exception as e:
        raise ValueError(f"Failed to generate key pair: {str(e)}")
    
    # Get node's public key
    try:
        res = sdk.confidential_node_public_key_selection.select_node_public_key(model_name=model)
        if not res or not res.public_key:
            raise ValueError("Failed to retrieve node public key")
        public_key_node = res.public_key
    except Exception as e:
        raise ValueError(f"Failed to get node public key: {str(e)}")

    # Generate a random salt and create shared secret
    try:
        salt = secrets.token_bytes(24)
        shared_secret = private_key.exchange(public_key_node)
        encryption_key = derive_key(shared_secret, salt)
        cipher = AESGCM(encryption_key)
        nonce = secrets.token_bytes(12)
    except Exception as e:
        raise ValueError(f"Failed to setup encryption: {str(e)}")
    
    # Encrypt the message
    try:
        message = chat_completions_request_body.model_dump_json().encode('utf-8')
        plaintext_body_hash = calculate_hash(message)
        ciphertext = cipher.encrypt(nonce, message, None)
        
        # Convert binary data to base64 strings
        return EncryptedMessage(
            ciphertext=base64.b64encode(ciphertext).decode('utf-8'),
            client_dh_public_key=base64.b64encode(public_key.public_bytes()).decode('utf-8'),
            nonce=base64.b64encode(nonce).decode('utf-8'),
            plaintext_body_hash=base64.b64encode(plaintext_body_hash).decode('utf-8'),
            salt=base64.b64encode(salt).decode('utf-8')
        )
    except Exception as e:
        raise ValueError(f"Failed to encrypt message: {str(e)}")
