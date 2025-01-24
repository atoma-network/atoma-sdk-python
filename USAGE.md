<!-- Start SDK Example Usage [usage] -->
```python
# Synchronous Example
from atoma_sdk import AtomaSDK
import os

with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as atoma_sdk:

    res = atoma_sdk.chat.create(messages=[
        {
            "content": "Hello! How can you help me today?",
            "role": "user",
        },
    ], model="meta-llama/Llama-3.3-70B-Instruct", frequency_penalty=0, max_tokens=2048, n=1, presence_penalty=0, seed=123, stop=[
        "json([\"stop\", \"halt\"])",
    ], temperature=0.7, top_p=1, user="user-1234")

    # Handle response
    print(res)
```

</br>

The same SDK client can also be used to make asychronous requests by importing asyncio.
```python
# Asynchronous Example
import asyncio
from atoma_sdk import AtomaSDK
import os

async def main():
    async with AtomaSDK(
        bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
    ) as atoma_sdk:

        res = await atoma_sdk.chat.create_async(messages=[
            {
                "content": "Hello! How can you help me today?",
                "role": "user",
            },
        ], model="meta-llama/Llama-3.3-70B-Instruct", frequency_penalty=0, max_tokens=2048, n=1, presence_penalty=0, seed=123, stop=[
            "json([\"stop\", \"halt\"])",
        ], temperature=0.7, top_p=1, user="user-1234")

        # Handle response
        print(res)

asyncio.run(main())
```
<!-- End SDK Example Usage [usage] -->