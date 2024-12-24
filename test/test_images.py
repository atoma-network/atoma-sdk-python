import os
import pytest
from dotenv import load_dotenv
from atoma_sdk import AtomaSDK

# Load environment variables
load_dotenv()

BEARER_AUTH = os.getenv("ATOMASDK_BEARER_AUTH")
IMAGES_URL = os.getenv("IMAGES_URL")
IMAGES_MODEL = os.getenv("IMAGES_MODEL")

@pytest.fixture
def client():
    return AtomaSDK(
        bearer_auth=BEARER_AUTH,
        server_url=IMAGES_URL
    )

def test_image_generation_basic(client):
    response = client.images.generate(
        model=IMAGES_MODEL,
        n=1,
        prompt="A beautiful sunset over mountains"
    )
    
    assert response is not None
    assert response.created is not None
    assert len(response.data) > 0
    assert response.data[0].url is not None
    assert response.data[0].revised_prompt is not None

def test_image_generation_with_options(client):
    response = client.images.generate(
        model=IMAGES_MODEL,
        n=1,
        prompt="A beautiful sunset over mountains",
        size="1024x1024",
        quality="hd",
        style="natural"
    )
    
    assert response is not None
    assert response.created is not None
    assert len(response.data) > 0
    assert response.data[0].url is not None
    assert response.data[0].revised_prompt is not None

@pytest.mark.asyncio
async def test_image_generation_async(client):
    response = await client.images.generate_async(
        model=IMAGES_MODEL,
        n=1,
        prompt="A beautiful sunset over mountains"
    )
    
    assert response is not None
    assert response.created is not None
    assert len(response.data) > 0
    assert response.data[0].url is not None
    assert response.data[0].revised_prompt is not None