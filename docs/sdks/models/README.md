# Models
(*models*)

## Overview

OpenAI's API models v1 endpoint

### Available Operations

* [models_handler](#models_handler) - List models

## models_handler

This endpoint mimics the OpenAI models endpoint format, returning a list of
available models with their associated metadata and permissions. Each model
includes standard OpenAI-compatible fields to ensure compatibility with
existing OpenAI client libraries.

# Arguments

* `state` - The shared application state containing the list of available models

# Returns

Returns a JSON response containing:
* An "object" field set to "list"
* A "data" array containing model objects with the following fields:
  - id: The model identifier
  - object: Always set to "model"
  - created: Timestamp (currently hardcoded)
  - owned_by: Set to "atoma"
  - root: Same as the model id
  - parent: Set to null
  - max_model_len: Maximum context length (currently hardcoded to 2048)
  - permission: Array of permission objects describing model capabilities

# Example Response

```json
{
  "object": "list",
  "data": [
    {
      "id": "meta-llama/Llama-3.1-70B-Instruct",
      "object": "model",
      "created": 1730930595,
      "owned_by": "atoma",
      "root": "meta-llama/Llama-3.1-70B-Instruct",
      "parent": null,
      "max_model_len": 2048,
      "permission": [
        {
          "id": "modelperm-meta-llama/Llama-3.1-70B-Instruct",
          "object": "model_permission",
          "created": 1730930595,
          "allow_create_engine": false,
          "allow_sampling": true,
          "allow_logprobs": true,
          "allow_search_indices": false,
          "allow_view": true,
          "allow_fine_tuning": false,
          "organization": "*",
          "group": null,
          "is_blocking": false
        }
      ]
    }
  ]
}
```

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os

with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as atoma_sdk:

    res = atoma_sdk.models.models_handler()

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