# Models
(*models*)

## Overview

OpenAI's API models v1 endpoint

### Available Operations

* [list](#list) - List models
* [get_all](#get_all) - OpenRouter models listing endpoint

## list

This endpoint mimics the OpenAI models endpoint format, returning a list of
available models with their associated metadata. Each model includes standard
OpenAI-compatible fields to ensure compatibility with existing OpenAI client libraries.

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os


with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as as_client:

    res = as_client.models.list()

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                           | Type                                                                | Required                                                            | Description                                                         |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `retries`                                                           | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)    | :heavy_minus_sign:                                                  | Configuration to override the default retry behavior of the client. |

### Response

**[models.ModelList](../../models/modellist.md)**

### Errors

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.APIError | 4XX, 5XX        | \*/\*           |

## get_all

This endpoint returns a list of available models from the OpenRouter
models file. The file is expected to be in JSON format and contains
information about the models, including their IDs and other metadata.

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os


with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as as_client:

    res = as_client.models.get_all()

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                           | Type                                                                | Required                                                            | Description                                                         |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `retries`                                                           | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)    | :heavy_minus_sign:                                                  | Configuration to override the default retry behavior of the client. |

### Response

**[Any](../../models/.md)**

### Errors

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.APIError | 4XX, 5XX        | \*/\*           |