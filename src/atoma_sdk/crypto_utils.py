from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import secrets
import base64
import hashlib
import json

from atoma_sdk.models.confidentialcomputerequest import ConfidentialComputeRequest
from atoma_sdk.models.confidentialcomputeresponse import ConfidentialComputeResponse
from atoma_sdk.nodes import Nodes

SALT_SIZE = 16
"""The salt size (16 bytes).
This value is compliant with the NIST SP 800-132 recommendation
(see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf) and it
agrees with the value used by the atoma-node infrastructure
(see https://github.com/atoma-network/atoma-node/blob/main/atoma-utils/src/lib.rs#L38)
"""

NONCE_SIZE = 12
"""The nonce size (12 bytes).
This value is compliant with the NIST SP 800-132 recommendation
(see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf) and it
agrees with the value used by the atoma-node infrastructure
(see https://github.com/atoma-network/atoma-node/blob/main/atoma-utils/src/lib.rs#L35)
"""

DEFAULT_WIDTH_SIZE = 1024

DEFAULT_HEIGHT_SIZE = 1024

def derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    try:
        if not isinstance(shared_secret, bytes) or not shared_secret:
            raise ValueError("shared_secret must be a non-empty bytes object")
        if not isinstance(salt, bytes) or not salt:
            raise ValueError("salt must be a non-empty bytes object")
            
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"",
        )
        return hkdf.derive(shared_secret)
    except Exception as e:
        raise ValueError(f"Failed to derive encryption key: {str(e)}") from e

def calculate_hash(data: bytes) -> bytes:
    try:
        # Using BLAKE2b with 32 bytes (256 bits) digest size
        blake2b = hashlib.blake2b(digest_size=32)
        blake2b.update(data)
        return blake2b.digest()
    except Exception as e:
        raise ValueError(f"Failed to calculate hash: {str(e)}") from e
    
def encrypt_message(
        sdk,
        client_dh_private_key: X25519PrivateKey,
        request_body: BaseModel,
        model: str
) -> tuple[X25519PublicKey, bytes, ConfidentialComputeRequest]:
    # Generate our private key
    try:
        client_dh_public_key = client_dh_private_key.public_key()
    except Exception as e:
        raise ValueError(f"Failed to generate key pair: {str(e)}") from e
    

    # build Nodes sdk
    sdk_nodes = Nodes(sdk.sdk_configuration)
    
    # Get node's public key
    try:
        res = sdk_nodes.nodes_create_lock(model=model)
        if not res or not res.public_key:
            raise ValueError("Failed to retrieve node public key")
        node_dh_public_key_encoded = res.public_key
        node_dh_public_key_bytes = base64.b64decode(node_dh_public_key_encoded)
        node_dh_public_key = X25519PublicKey.from_public_bytes(node_dh_public_key_bytes)
        stack_small_id = res.stack_small_id
    except Exception as e:
        raise ValueError(f"Failed to get node public key: {str(e)}") from e

    # Generate a random salt and create shared secret
    try:
        salt = secrets.token_bytes(SALT_SIZE)
        shared_secret = client_dh_private_key.exchange(node_dh_public_key)
        encryption_key = derive_key(shared_secret, salt)
        cipher = AESGCM(encryption_key)
        nonce = secrets.token_bytes(NONCE_SIZE)
    except Exception as e:
        raise ValueError(f"Failed to setup encryption: {str(e)}") from e
    
    # Get num_compute_units based on request type
    num_compute_units = None
    try:
        # For image generations compute units is number of pixels
        if hasattr(request_body, 'width') and hasattr(request_body, 'height'):
            width = getattr(request_body, 'width', DEFAULT_WIDTH_SIZE)  # Default to 1024 if not specified
            height = getattr(request_body, 'height', DEFAULT_HEIGHT_SIZE)  # Default to 1024 if not specified
            num_compute_units = width * height

        # For chat completions compute units is max_tokens
        if hasattr(request_body, 'max_tokens'):
            num_compute_units = request_body.max_tokens
        
        # For embeddings (CreateEmbeddingRequest), let server calculate tokens
        # No need to set num_compute_units as it defaults to None

    except Exception as e:
        raise ValueError(f"Failed to calculate compute units: {str(e)}") from e

    # Encrypt the message
    try:
        message = request_body.model_dump_json().encode('utf-8')
        plaintext_body_hash = calculate_hash(message)
        ciphertext = cipher.encrypt(nonce, message, None)
        
        # Convert binary data to base64 strings
        return node_dh_public_key, salt, ConfidentialComputeRequest(
            ciphertext=base64.b64encode(ciphertext).decode('utf-8'),
            client_dh_public_key=base64.b64encode(client_dh_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode('utf-8'),
            model_name=model,
            node_dh_public_key=base64.b64encode(node_dh_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode('utf-8'),
            nonce=base64.b64encode(nonce).decode('utf-8'),
            plaintext_body_hash=base64.b64encode(plaintext_body_hash).decode('utf-8'),
            salt=base64.b64encode(salt).decode('utf-8'),
            stack_small_id=stack_small_id,
            num_compute_units=num_compute_units,
            stream=getattr(request_body, 'stream', False),
        )
    except Exception as e:
        raise ValueError(f"Failed to encrypt message: {str(e)}") from e

def decrypt_message(
        client_dh_private_key: X25519PrivateKey,
        node_dh_public_key: X25519PublicKey,
        salt: bytes,
        encrypted_message: ConfidentialComputeResponse
) -> bytes:
    try:
        # Decode base64 values
        ciphertext = base64.b64decode(encrypted_message.ciphertext)
        nonce = base64.b64decode(encrypted_message.nonce)
        expected_hash = encrypted_message.response_hash
        
        # Load node's public key and create shared secret
        shared_secret = client_dh_private_key.exchange(node_dh_public_key)
        
        # Derive encryption key
        encryption_key = derive_key(shared_secret, salt)
        cipher = AESGCM(encryption_key)
        
        # Decrypt the message
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        
        # Verify hash if provided and not a final stream chunk
        if expected_hash:
            decoded_json = json.loads(plaintext)
            choices = decoded_json.get('choices', [])
            actual_hash_bytes = calculate_hash(plaintext)
            expected_hash_bytes = base64.b64decode(expected_hash)

            if not secrets.compare_digest(actual_hash_bytes, expected_hash_bytes):
                print(f"plaintext: {plaintext}\n")
                print(f"expected_hash: {expected_hash}\n")
                print(f"actual_hash: {actual_hash_bytes}\n")
                raise ValueError("Message hash verification failed")

        return plaintext
        
    except Exception as e:
        raise ValueError(f"Failed to decrypt message: {str(e)}") from e
