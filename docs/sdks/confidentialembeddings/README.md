# ConfidentialEmbeddings
(*confidential_embeddings*)

## Overview

Atoma's API confidential embeddings v1 endpoint

### Available Operations

* [create](#create) - Create confidential embeddings

## create

This endpoint follows the OpenAI API format for generating vector embeddings from input text,
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
* `Ok(Response)` - The embeddings response from the processing node
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

    res = atoma_sdk.confidential_embeddings.create(request={})

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                               | Type                                                                    | Required                                                                | Description                                                             |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `request`                                                               | [models.CreateEmbeddingRequest](../../models/createembeddingrequest.md) | :heavy_check_mark:                                                      | The request object to use for the request.                              |
| `retries`                                                               | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)        | :heavy_minus_sign:                                                      | Configuration to override the default retry behavior of the client.     |

### Response

**[models.CreateEmbeddingResponse](../../models/createembeddingresponse.md)**

### Errors

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.APIError | 4XX, 5XX        | \*/\*           |