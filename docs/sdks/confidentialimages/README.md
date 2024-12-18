# ConfidentialImages
(*confidential_images*)

## Overview

Atoma's API confidential images v1 endpoint

### Available Operations

* [generate](#generate) - Create confidential image generations

## generate

This endpoint follows the OpenAI API format for generating images,
but with confidential processing (through AEAD encryption and TEE hardware).
The handler receives pre-processed metadata from middleware and forwards the request to
the selected node.

Note: Authentication, node selection, initial request validation and encryption
are handled by middleware before this handler is called.

# Arguments
* `metadata` - Pre-processed request metadata containing node information and compute units
* `state` - The shared proxy state containing configuration and runtime information
* `headers` - HTTP headers from the incoming request
* `payload` - The JSON request body containing the model and input text

# Returns
* `Ok(Response)` - The image generations response from the processing node
* `Err(StatusCode)` - An error status code if any step fails

# Errors
* `INTERNAL_SERVER_ERROR` - Processing or node communication failures

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os

with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as atoma_sdk:

    res = atoma_sdk.confidential_images.generate(model="Model X", n=447445, prompt="<value>")

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