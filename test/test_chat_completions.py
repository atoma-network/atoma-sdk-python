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
    completion = client.chat.create(
        model=CHAT_COMPLETIONS_MODEL,
        messages=[
            {"role": "developer", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello!"}
        ]
    )

    print(completion.choices[0].message)
    
    assert completion is not None
    assert len(completion.choices) > 0
    assert completion.choices[0].message.content is not None

def test_chat_completion_with_system_message(client):
    completion = client.chat.create(
        model=CHAT_COMPLETIONS_MODEL,
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello!"}
        ]
    )
    
    assert completion is not None
    assert len(completion.choices) > 0
    assert completion.choices[0].message.content is not None

@pytest.mark.asyncio
async def test_chat_completion_async(client):
    completion = await client.chat.create_async(
        model=CHAT_COMPLETIONS_MODEL,
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello!"}
        ]
    )
    
    assert completion is not None
    assert len(completion.choices) > 0
    assert completion.choices[0].message.content is not None
