<!-- Start SDK Example Usage [usage] -->
```python
# Synchronous Example
from atoma_sdk import AtomaSDK
import os


with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as as_client:

    res = as_client.completions.create(model="meta-llama/Llama-3.3-70B-Instruct", prompt=[
        "<value>",
        "<value>",
    ], frequency_penalty=0, logit_bias={
        "1234567890": 0.5,
        "1234567891": -0.5,
    }, logprobs=1, n=1, presence_penalty=0, seed=123, stop=[
        "json([\"stop\", \"halt\"])",
    ], stream=False, suffix="json(\"\n\")", temperature=0.7, top_p=1, user="user-1234")

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
    ) as as_client:

        res = await as_client.completions.create_async(model="meta-llama/Llama-3.3-70B-Instruct", prompt=[
            "<value>",
            "<value>",
        ], frequency_penalty=0, logit_bias={
            "1234567890": 0.5,
            "1234567891": -0.5,
        }, logprobs=1, n=1, presence_penalty=0, seed=123, stop=[
            "json([\"stop\", \"halt\"])",
        ], stream=False, suffix="json(\"\n\")", temperature=0.7, top_p=1, user="user-1234")

        # Handle response
        print(res)

asyncio.run(main())
```
<!-- End SDK Example Usage [usage] -->