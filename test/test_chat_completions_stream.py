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

def test_chat_completion_stream(client):
    messages = [
        ChatCompletionMessage(
            role="user",
            content="Count from 1 to 5 slowly."
        )
    ]
    
    response = client.chat.create_stream(
        messages=messages,
        model=CHAT_COMPLETIONS_MODEL
    )
    
    chunks_received = 0
    content_received = False
    
    with response as event_stream:
        for event in event_stream:
            assert event is not None
            assert event.data is not None
            assert len(event.data.choices) > 0
            
            # Check if we received any content
            if event.data.choices[0].delta.content:
                content_received = True
            
            chunks_received += 1
    
    assert chunks_received > 0
    assert content_received

@pytest.mark.asyncio
async def test_chat_completion_stream_async(client):
    messages = [
        ChatCompletionMessage(
            role="user",
            content="Count from 1 to 5 slowly."
        )
    ]
    
    response = await client.chat.create_stream_async(
        messages=messages,
        model=CHAT_COMPLETIONS_MODEL
    )
    
    chunks_received = 0
    content_received = False
    
    async with response as event_stream:
        async for event in event_stream:
            assert event is not None
            assert event.data is not None
            assert len(event.data.choices) > 0
            
            # Check if we received any content
            if event.data.choices[0].delta.content:
                content_received = True
            
            chunks_received += 1
    
    assert chunks_received > 0
    assert content_received

def test_chat_completion_stream_with_system_message(client):
    messages = [
        ChatCompletionMessage(
            role="system",
            content="You are a helpful assistant that speaks like Shakespeare."
        ),
        ChatCompletionMessage(
            role="user",
            content="Count from 1 to 5."
        )
    ]
    
    response = client.chat.create_stream(
        messages=messages,
        model=CHAT_COMPLETIONS_MODEL
    )
    
    chunks_received = 0
    content_received = False
    
    with response as event_stream:
        for event in event_stream:
            assert event is not None
            assert event.data is not None
            assert len(event.data.choices) > 0
            
            # Check if we received any content
            if event.data.choices[0].delta.content:
                content_received = True
            
            chunks_received += 1
    
    assert chunks_received > 0
    assert content_received