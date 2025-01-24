from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import secrets
import base64
import hashlib

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
    """Derives an encryption key using HKDF (HMAC-based Key Derivation Function).

    This function uses HKDF with SHA-256 to derive a 32-byte (256-bit) encryption key
    from a shared secret and salt. The implementation follows cryptographic best practices
    for key derivation.

    Args:
        shared_secret (bytes): The shared secret from which to derive the key.
            Must be a non-empty bytes object, typically obtained from Diffie-Hellman key exchange.
        salt (bytes): Random salt value used in the key derivation.
            Must be a non-empty bytes object, typically 16 bytes long.

    Returns:
        bytes: A 32-byte derived encryption key.

    Raises:
        ValueError: If shared_secret or salt is empty or not a bytes object,
            or if key derivation fails for any reason.

    Example:
        >>> shared_secret = b"some_shared_secret"
        >>> salt = secrets.token_bytes(16)
        >>> key = derive_key(shared_secret, salt)
    """
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
    """Calculate a cryptographic hash of the input data using BLAKE2b.

    This function computes a 32-byte (256-bit) BLAKE2b hash of the input data.
    BLAKE2b is a cryptographically secure hash function that provides better
    performance than SHA-3 and is considered a suitable replacement for SHA-2.

    Args:
        data (bytes): The input data to be hashed. Must be a non-empty bytes object.

    Returns:
        bytes: A 32-byte BLAKE2b hash of the input data.

    Raises:
        ValueError: If data is not a bytes object or if hashing fails for any reason.

    Example:
        >>> message = b"Hello, World!"
        >>> hash_value = calculate_hash(message)
    """
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
    """Encrypts a request message using X25519 key exchange and AES-GCM encryption.

    This function performs several cryptographic operations to securely encrypt a request:
    1. Generates a public key from the client's private key
    2. Retrieves the node's public key via API
    3. Performs X25519 key exchange to create a shared secret
    4. Derives an encryption key using HKDF
    5. Encrypts the message using AES-GCM
    
    Args:
        sdk: The SDK instance containing configuration for API calls
        client_dh_private_key (X25519PrivateKey): The client's X25519 private key for key exchange
        request_body (BaseModel): A Pydantic model containing the request data to encrypt
        model (str): The model identifier to use for the request

    Returns:
        tuple[X25519PublicKey, bytes, ConfidentialComputeRequest]: A tuple containing:
            - node_dh_public_key: The node's public key used for encryption
            - salt: The random salt used in key derivation
            - ConfidentialComputeRequest: The encrypted request containing:
                - ciphertext: The encrypted message
                - client_dh_public_key: Client's public key (base64)
                - model_name: The requested model identifier
                - node_dh_public_key: Node's public key (base64)
                - nonce: Random nonce used in encryption (base64)
                - plaintext_body_hash: Hash of original message (base64)
                - salt: Random salt used in key derivation (base64)
                - stack_small_id: Identifier for the processing node
                - num_compute_units: Computed resource units (pixels or tokens)
                - stream: Whether to stream the response

    Raises:
        ValueError: If any step of the encryption process fails, with a descriptive error message

    Example:
        >>> from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        >>> from atoma_sdk.nodes import Nodes
        >>> 
        >>> # Initialize SDK and create request
        >>> sdk = AtomaSDK(...)
        >>> private_key = X25519PrivateKey.generate()
        >>> request = ChatCompletionRequest(messages=[{"role": "user", "content": "A sunset"}])
        >>> 
        >>> # Encrypt the request
        >>> node_key, salt, encrypted_request = encrypt_message(
        ...     sdk,
        ...     private_key,
        ...     request,
        ...     "meta-llama/meta-llama-3.3-70B-Instruct"
        ... )
    """
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
    """Decrypts a response message using X25519 key exchange and AES-GCM decryption.

    This function performs several cryptographic operations to securely decrypt a response:
    1. Decodes the base64-encoded ciphertext and nonce
    2. Uses the client's private key and node's public key to recreate the shared secret
    3. Derives the encryption key using HKDF with the original salt
    4. Decrypts the message using AES-GCM
    5. Verifies the message hash (if provided) to ensure integrity

    Args:
        client_dh_private_key (X25519PrivateKey): The client's X25519 private key used in the original encryption
        node_dh_public_key (X25519PublicKey): The node's X25519 public key used in the original encryption
        salt (bytes): The salt value used in the original key derivation
        encrypted_message (ConfidentialComputeResponse): The encrypted response containing:
            - ciphertext: The encrypted message (base64)
            - nonce: The nonce used in encryption (base64)
            - response_hash: Hash of the response for verification (base64, optional)

    Returns:
        bytes: The decrypted plaintext message

    Raises:
        ValueError: If any step of the decryption process fails, including:
            - Base64 decoding errors
            - Key exchange failures
            - Decryption failures
            - Hash verification failures
            With a descriptive error message

    Example:
        >>> from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        >>> from atoma_sdk.models.confidentialcomputeresponse import ConfidentialComputeResponse
        >>> 
        >>> # Using previously stored keys and salt from encryption
        >>> decrypted = decrypt_message(
        ...     client_private_key,
        ...     node_public_key,
        ...     salt,
        ...     encrypted_response
        ... )
        >>> print(decrypted.decode('utf-8'))
    """
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
        
        # Verify hash
        if expected_hash:
            actual_hash_bytes = calculate_hash(plaintext)
            expected_hash_bytes = base64.b64decode(expected_hash)

            if not secrets.compare_digest(actual_hash_bytes, expected_hash_bytes):
                raise ValueError("Message hash verification failed")

        return plaintext
        
    except Exception as e:
        raise ValueError(f"Failed to decrypt message: {str(e)}") from e
