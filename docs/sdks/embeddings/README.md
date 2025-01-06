# Embeddings
(*embeddings*)

## Overview

OpenAI's API embeddings v1 endpoint

### Available Operations

* [create](#create) - Create embeddings

## create

This endpoint follows the OpenAI API format for generating vector embeddings from input text.
The handler receives pre-processed metadata from middleware and forwards the request to
the selected node.

# Returns
* `Ok(Response)` - The embeddings response from the processing node
* `Err(AtomaProxyError)` - An error status code if any step fails

## Errors
* `INTERNAL_SERVER_ERROR` - Processing or node communication failures

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os

with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as atoma_sdk:

    res = atoma_sdk.embeddings.create(input_="<value>", model="LeBaron")

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                                                                        | Type                                                                                                             | Required                                                                                                         | Description                                                                                                      |
| ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `input`                                                                                                          | [models.EmbeddingInput](../../models/embeddinginput.md)                                                          | :heavy_check_mark:                                                                                               | N/A                                                                                                              |
| `model`                                                                                                          | *str*                                                                                                            | :heavy_check_mark:                                                                                               | ID of the model to use.                                                                                          |
| `dimensions`                                                                                                     | *OptionalNullable[int]*                                                                                          | :heavy_minus_sign:                                                                                               | The number of dimensions the resulting output embeddings should have.<br/>Only supported in text-embedding-3 models. |
| `encoding_format`                                                                                                | *OptionalNullable[str]*                                                                                          | :heavy_minus_sign:                                                                                               | The format to return the embeddings in. Can be "float" or "base64".<br/>Defaults to "float"                      |
| `user`                                                                                                           | *OptionalNullable[str]*                                                                                          | :heavy_minus_sign:                                                                                               | A unique identifier representing your end-user, which can help OpenAI to monitor and detect abuse.               |
| `retries`                                                                                                        | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)                                                 | :heavy_minus_sign:                                                                                               | Configuration to override the default retry behavior of the client.                                              |

### Response

**[models.CreateEmbeddingResponse](../../models/createembeddingresponse.md)**

### Errors

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.APIError | 4XX, 5XX        | \*/\*           |