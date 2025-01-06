# Images
(*images*)

## Overview

OpenAI's API images v1 endpoint

### Available Operations

* [generate](#generate) - Create image

## generate

This endpoint processes requests to generate images using AI models by forwarding them
to the appropriate AI node. The request metadata and compute units have already been
validated by middleware before reaching this handler.

## Errors
* Returns various status codes based on the underlying `handle_image_generation_response`:
  - `INTERNAL_SERVER_ERROR` - If there's an error communicating with the AI node

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os

with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as atoma_sdk:

    res = atoma_sdk.images.generate(model="Model X", prompt="<value>", n=447445)

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                                                                                         | Type                                                                                                                              | Required                                                                                                                          | Description                                                                                                                       |
| --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `model`                                                                                                                           | *str*                                                                                                                             | :heavy_check_mark:                                                                                                                | The model to use for image generation.                                                                                            |
| `prompt`                                                                                                                          | *str*                                                                                                                             | :heavy_check_mark:                                                                                                                | A text description of the desired image(s). The maximum length is 1000 characters.                                                |
| `n`                                                                                                                               | *OptionalNullable[int]*                                                                                                           | :heavy_minus_sign:                                                                                                                | The number of images to generate. Defaults to 1.                                                                                  |
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