import os
import pytest
from dotenv import load_dotenv
from atoma_sdk import AtomaSDK
from atoma_sdk.models import ChatCompletionMessage

# Load environment variables
load_dotenv()

BEARER_AUTH = os.getenv("ATOMASDK_BEARER_AUTH")
CHAT_COMPLETIONS_URL = os.getenv("CHAT_COMPLETIONS_URL")
CHAT_COMPLETIONS_MODEL = os.getenv("CHAT_COMPLETIONS_MODEL")

@pytest.fixture
def client():
    return AtomaSDK(
        bearer_auth=BEARER_AUTH,
        server_url=CHAT_COMPLETIONS_URL
    )

def test_chat_completion_basic(client):
    messages = [
        ChatCompletionMessage(
            role="user",
            content="Say hello!"
        )
    ]
    
    response = client.confidential_chat.create(
        messages=messages,
        model=CHAT_COMPLETIONS_MODEL
    )
    
    assert response is not None
    assert len(response.choices) > 0
    assert response.choices[0].message.content is not None

def test_chat_completion_stream(client):
    messages = [
        ChatCompletionMessage(
            role="user",
            content="Do exactly what I say. Tell me three words."
        )
    ]
    
    stream = client.confidential_chat.create_stream(
        messages=messages,
        model=CHAT_COMPLETIONS_MODEL
    )
    
    # Collect all chunks to verify the response
    chunks = []
    for chunk in stream:
        assert chunk is not None
        chunks.append(chunk)
    
    # Verify we got multiple chunks
    assert len(chunks) > 1
    
    # Verify the chunks are properly formatted
    for chunk in chunks:
        assert hasattr(chunk, 'choices')
        assert len(chunk.choices) > 0
        assert chunk.choices[0].delta is not None
        
    # Verify the first chunk has role
    assert chunks[0].choices[0].delta.role == "assistant"
    
    # Verify some chunks have content
    content_chunks = [c for c in chunks if c.choices[0].delta.content is not None]
    assert len(content_chunks) > 0

if __name__ == "__main__":
    #test_chat_completion_basic(AtomaSDK(bearer_auth=BEARER_AUTH, server_url=CHAT_COMPLETIONS_URL))
    test_chat_completion_stream(AtomaSDK(bearer_auth=BEARER_AUTH, server_url=CHAT_COMPLETIONS_URL))