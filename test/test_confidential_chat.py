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
    assert response.choices[0].message.role == "assistant"


if __name__ == "__main__":
    test_chat_completion_basic(AtomaSDK(bearer_auth=BEARER_AUTH, server_url=CHAT_COMPLETIONS_URL))