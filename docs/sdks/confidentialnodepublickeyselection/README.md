# ConfidentialNodePublicKeySelection
(*confidential_node_public_key_selection*)

## Overview

### Available Operations

* [select_node_public_key](#select_node_public_key) - Handles requests to select a node's public key for confidential compute operations.

## select_node_public_key

This endpoint attempts to find a suitable node and retrieve its public key for encryption
through a two-step process:

1. First, it tries to select an existing node with a public key directly.
2. If no node is immediately available, it falls back to finding the cheapest compatible node
   and acquiring a new stack entry for it.

# Parameters
- `state`: The shared proxy state containing connections to the state manager and Sui
- `metadata`: Request metadata from middleware
- `request`: JSON payload containing the requested model name

# Returns
Returns a `Result` containing either:
- `Json<SelectNodePublicKeyResponse>` with:
  - The selected node's public key (base64 encoded)
  - The node's small ID
  - Optional stack entry digest (if a new stack entry was acquired)
- `AtomaProxyError` error if:
  - `INTERNAL_SERVER_ERROR` - Communication errors or missing node public keys
  - `SERVICE_UNAVAILABLE` - No nodes available for confidential compute

# Example Response
```json
{
    "public_key": [base64_encoded_bytes],
    "node_small_id": 123,
    "stack_entry_digest": "transaction_digest_string"
}
```

This endpoint is specifically designed for confidential compute scenarios where
requests need to be encrypted before being processed by nodes.

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os

with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as atoma_sdk:

    res = atoma_sdk.confidential_node_public_key_selection.select_node_public_key(model_name="<value>")

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                           | Type                                                                | Required                                                            | Description                                                         |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `model_name`                                                        | *str*                                                               | :heavy_check_mark:                                                  | The request model name                                              |
| `retries`                                                           | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)    | :heavy_minus_sign:                                                  | Configuration to override the default retry behavior of the client. |

### Response

**[Any](../../models/.md)**

### Errors

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.APIError | 4XX, 5XX        | \*/\*           |