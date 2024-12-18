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
    
    response = client.chat.create(
        messages=messages,
        model=CHAT_COMPLETIONS_MODEL
    )
    
    assert response is not None
    assert len(response.choices) > 0
    assert response.choices[0].message.content is not None
    assert response.choices[0].message.role == "assistant"

def test_chat_completion_with_system_message(client):
    messages = [
        ChatCompletionMessage(
            role="system",
            content="You are a helpful assistant that speaks like Shakespeare."
        ),
        ChatCompletionMessage(
            role="user",
            content="Say hello!"
        )
    ]
    
    response = client.chat.create(
        messages=messages,
        model=CHAT_COMPLETIONS_MODEL
    )
    
    assert response is not None
    assert len(response.choices) > 0
    assert response.choices[0].message.content is not None
    assert response.choices[0].message.role == "assistant"

@pytest.mark.asyncio
async def test_chat_completion_async(client):
    messages = [
        ChatCompletionMessage(
            role="user",
            content="Say hello!"
        )
    ]
    
    response = await client.chat.create_async(
        messages=messages,
        model=CHAT_COMPLETIONS_MODEL
    )
    
    assert response is not None
    assert len(response.choices) > 0
    assert response.choices[0].message.content is not None
    assert response.choices[0].message.role == "assistant"