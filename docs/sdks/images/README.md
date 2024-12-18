# Images
(*images*)

## Overview

OpenAI's API images v1 endpoint

### Available Operations

* [generate](#generate) - Create image generation

## generate

This endpoint processes requests to generate images using AI models by forwarding them
to the appropriate AI node. The request metadata and compute units have already been
validated by middleware before reaching this handler.

# Arguments
* `metadata` - Extension containing pre-processed request metadata (node address, compute units, etc.)
* `state` - Application state containing configuration and shared resources
* `headers` - HTTP headers from the incoming request
* `payload` - JSON payload containing image generation parameters

# Returns
* `Result<Response<Body>, StatusCode>` - The processed response from the AI node or an error status

# Errors
* Returns various status codes based on the underlying `handle_image_generation_response`:
  - `INTERNAL_SERVER_ERROR` - If there's an error communicating with the AI node

# Example Payload
```json
{
    "model": "stable-diffusion-v1-5",
    "n": 1,
    "size": "1024x1024"
}
```

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os

with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as atoma_sdk:

    res = atoma_sdk.images.generate(model="Model X", n=447445, prompt="<value>")

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                                                                                         | Type                                                                                                                              | Required                                                                                                                          | Description                                                                                                                       |
| --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `model`                                                                                                                           | *str*                                                                                                                             | :heavy_check_mark:                                                                                                                | The model to use for image generation.                                                                                            |
| `n`                                                                                                                               | *int*                                                                                                                             | :heavy_check_mark:                                                                                                                | The number of images to generate. Must be between 1 and 10.                                                                       |
| `prompt`                                                                                                                          | *str*                                                                                                                             | :heavy_check_mark:                                                                                                                | A text description of the desired image(s). The maximum length is 1000 characters.                                                |
| `quality`                                                                                                                         | *OptionalNullable[str]*                                                                                                           | :heavy_minus_sign:                                                                                                                | The quality of the image that will be generated.<br/>`hd` creates images with finer details and greater consistency across the image. |
| `response_format`                                                                                                                 | *OptionalNullable[str]*                                                                                                           | :heavy_minus_sign:                                                                                                                | The format in which the generated images are returned.                                                                            |
| `size`                                                                                                                            | *OptionalNullable[str]*                                                                                                           | :heavy_minus_sign:                                                                                                                | The size of the generated images.                                                                                                 |
| `style`                                                                                                                           | *OptionalNullable[str]*                                                                                                           | :heavy_minus_sign:                                                                                                                | The style of the generated images.                                                                                                |
| `user`                                                                                                                            | *OptionalNullable[str]*                                                                                                           | :heavy_minus_sign:                                                                                                                | A unique identifier representing your end-user, which can help OpenAI to monitor and detect abuse.                                |
| `retries`                                                                                                                         | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)                                                                  | :heavy_minus_sign:                                                                                                                | Configuration to override the default retry behavior of the client.                                                               |

### Response

**[models.CreateImageResponse](../../models/createimageresponse.md)**

### Errors

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.APIError | 4XX, 5XX        | \*/\*           |