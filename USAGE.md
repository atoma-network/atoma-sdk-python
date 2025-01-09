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
            "content": "<value>",
            "role": "<value>",
        },
    ], model="LeBaron")

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
                "content": "<value>",
                "role": "<value>",
            },
        ], model="LeBaron")

        # Handle response
        print(res)

asyncio.run(main())
```
<!-- End SDK Example Usage [usage] -->