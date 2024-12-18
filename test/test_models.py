import os
import pytest
from dotenv import load_dotenv
from atoma_sdk import AtomaSDK

# Load environment variables
load_dotenv()

BEARER_AUTH = os.getenv("ATOMASDK_BEARER_AUTH")
BASE_URL = os.getenv("BASE_URL")

@pytest.fixture
def client():
    return AtomaSDK(
        bearer_auth=BEARER_AUTH,
        server_url=BASE_URL
    )

def test_models_handler(client):
    response = client.models.models_handler()

    assert response is not None
    assert response.get("data") is not None

@pytest.mark.asyncio
async def test_models_handler_async(client):
    response = await client.models.models_handler_async()
    assert response is not None
    assert response.get("data") is not None