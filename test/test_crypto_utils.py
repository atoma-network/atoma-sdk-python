import base64
import secrets
import pytest

# Ignore the warning about TestRequest constructor
pytest.mark.filterwarnings("ignore::pytest.PytestCollectionWarning")

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel
from atoma_sdk.crypto_utils import calculate_hash, derive_key, encrypt_message, decrypt_message
from atoma_sdk.models.confidentialcomputeresponse import ConfidentialComputeResponse


class TestRequest(BaseModel):
    message: str
    max_tokens: int = 100


@pytest.fixture
def client_keys():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def mock_sdk():
    class MockSDK:
        class MockKeySelection:
            def select_node_public_key(self, model_name: str):
                class MockResponse:
                    def __init__(self):
                        node_private_key = X25519PrivateKey.generate()
                        self.public_key = node_private_key.public_key().public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        )
                        self.stack_small_id = 123
                return MockResponse()
        
        def __init__(self):
            self.confidential_node_public_key_selection = self.MockKeySelection()
    
    return MockSDK()


def test_calculate_hash():
    # Test hash calculation with known input
    test_data = b"Hello, World!"
    hash_result = calculate_hash(test_data)
    
    # Verify hash properties
    assert len(hash_result) == 32  # BLAKE2b with 32 bytes digest size
    assert isinstance(hash_result, bytes)
    
    # Verify deterministic behavior
    hash_result2 = calculate_hash(test_data)
    assert hash_result == hash_result2
    
    # Verify different inputs produce different hashes
    different_data = b"Different data"
    different_hash = calculate_hash(different_data)
    assert hash_result != different_hash


def test_derive_key():
    # Test key derivation with known inputs
    shared_secret = secrets.token_bytes(32)
    salt = secrets.token_bytes(24)
    
    # Derive key
    key = derive_key(shared_secret, salt)
    
    # Verify key properties
    assert len(key) == 32  # Should be 32 bytes (256 bits)
    assert isinstance(key, bytes)
    
    # Verify deterministic behavior
    key2 = derive_key(shared_secret, salt)
    assert key == key2
    
    # Verify different inputs produce different keys
    different_secret = secrets.token_bytes(32)
    different_salt = secrets.token_bytes(24)
    
    key3 = derive_key(different_secret, salt)
    key4 = derive_key(shared_secret, different_salt)
    
    assert key != key3
    assert key != key4


def test_invalid_inputs():
    # Test invalid inputs for hash calculation
    with pytest.raises((ValueError, TypeError)):
        calculate_hash(None)
    
    # Test invalid inputs for key derivation
    with pytest.raises(ValueError):
        derive_key(None, b"salt")  # None is not bytes
    with pytest.raises(ValueError):
        derive_key(b"", b"salt")  # Empty bytes
    with pytest.raises(ValueError):
        derive_key(b"secret", b"")  # Empty salt
    with pytest.raises(ValueError):
        derive_key(b"secret", None)  # None is not bytes


def test_encryption_decryption(client_keys, mock_sdk):
    client_private_key, _ = client_keys
    request = TestRequest(message="Test message")
    
    # Test encryption
    node_public_key, salt, encrypted_request = encrypt_message(
        mock_sdk,
        client_private_key,
        request,
        "test-model"
    )
    
    # Verify encrypted request properties
    assert encrypted_request.ciphertext is not None
    assert encrypted_request.nonce is not None
    assert encrypted_request.salt is not None
    assert encrypted_request.model_name == "test-model"
    assert encrypted_request.num_compute_units == 100  # from max_tokens
    
    # Create mock response for decryption test
    mock_response = ConfidentialComputeResponse(
        ciphertext=encrypted_request.ciphertext,
        nonce=encrypted_request.nonce,
        response_hash=base64.b64encode(calculate_hash(request.model_dump_json().encode())).decode()
    )
    
    # Test decryption
    decrypted_data = decrypt_message(
        client_private_key,
        node_public_key,
        salt,
        mock_response
    )
    
    # Verify decrypted data matches original
    assert decrypted_data.decode() == request.model_dump_json() 