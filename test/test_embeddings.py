import os
import pytest
from dotenv import load_dotenv
from atoma_sdk import AtomaSDK

# Load environment variables
load_dotenv()

BEARER_AUTH = os.getenv("ATOMASDK_BEARER_AUTH")
EMBEDDINGS_URL = os.getenv("EMBEDDINGS_URL")
EMBEDDINGS_MODEL = os.getenv("EMBEDDINGS_MODEL")

@pytest.fixture
def client():
    return AtomaSDK(
        bearer_auth=BEARER_AUTH,
        server_url=EMBEDDINGS_URL
    )

def test_embeddings_basic(client):
    request = {
        "model": EMBEDDINGS_MODEL,
        "input": "The quick brown fox jumps over the lazy dog"
    }
    
    response = client.embeddings.create(request=request)
    
    assert response is not None
    assert len(response.data) > 0
    assert response.data[0].embedding is not None
    assert len(response.data[0].embedding) > 0
    assert response.data[0].index == 0
    assert response.data[0].object == "embedding"
    assert response.usage.prompt_tokens > 0
    assert response.usage.total_tokens > 0

def test_embeddings_batch(client):
    request = {
        "model": EMBEDDINGS_MODEL,
        "input": [
            "The quick brown fox jumps over the lazy dog",
            "The lazy dog sleeps while the quick brown fox jumps"
        ]
    }
    
    response = client.embeddings.create(request=request)
    
    assert response is not None
    assert len(response.data) == 2
    assert response.data[0].embedding is not None
    assert response.data[1].embedding is not None
    assert response.data[0].index == 0
    assert response.data[1].index == 1
    assert response.usage.prompt_tokens > 0
    assert response.usage.total_tokens > 0

@pytest.mark.asyncio
async def test_embeddings_async(client):
    request = {
        "model": EMBEDDINGS_MODEL,
        "input": "The quick brown fox jumps over the lazy dog"
    }
    
    response = await client.embeddings.create_async(request=request)
    
    assert response is not None
    assert len(response.data) > 0
    assert response.data[0].embedding is not None
    assert len(response.data[0].embedding) > 0
    assert response.data[0].index == 0
    assert response.data[0].object == "embedding"
    assert response.usage.prompt_tokens > 0
    assert response.usage.total_tokens > 0