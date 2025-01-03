# ConfidentialChat
(*confidential_chat*)

## Overview

Atoma's API confidential chat completions v1 endpoint

### Available Operations

* [create](#create) - Create confidential chat completion

## create

This handler processes chat completion requests in a confidential manner, providing additional
encryption and security measures for sensitive data processing. It supports both streaming and
non-streaming responses while maintaining data confidentiality through AEAD encryption and TEE hardware,
for full private AI compute.

# Arguments

* `metadata` - Extension containing request metadata including:
  * `endpoint` - The API endpoint being accessed
  * `node_address` - Address of the inference node
  * `node_id` - Identifier of the selected node
  * `num_compute_units` - Available compute units
  * `selected_stack_small_id` - Stack identifier
  * `salt` - Optional salt for encryption
  * `node_x25519_public_key` - Optional public key for encryption
  * `model_name` - Name of the AI model being used
* `state` - Shared application state (ProxyState)
* `headers` - HTTP request headers
* `payload` - The chat completion request body

# Returns

Returns a `Result` containing either:
* An HTTP response with the chat completion result
* A streaming SSE connection for real-time completions
* An `AtomaProxyError` error if the request processing fails

# Errors

Returns `AtomaProxyError::InvalidBody` if:
* The 'stream' field is missing or invalid in the payload

Returns `AtomaProxyError::InternalError` if:
* The inference service request fails
* Response processing encounters errors
* State manager updates fail

# Security Features

* Utilizes AEAD encryption for request/response data
* Supports TEE (Trusted Execution Environment) processing
* Implements secure key exchange using X25519
* Maintains confidentiality throughout the request lifecycle

# Example

```rust,ignore
let response = confidential_chat_completions_handler(
    Extension(metadata),
    State(state),
    headers,
    Json(payload)
).await?;
```

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os

with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as atoma_sdk:

    res = atoma_sdk.confidential_chat.create(ciphertext="<value>", client_dh_public_key="<value>", model_name="<value>", node_dh_public_key="<value>", nonce="<value>", plaintext_body_hash="<value>", salt="<value>", stack_small_id=486589)

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                                                                                                       | Type                                                                                                                                            | Required                                                                                                                                        | Description                                                                                                                                     |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `ciphertext`                                                                                                                                    | *str*                                                                                                                                           | :heavy_check_mark:                                                                                                                              | The encrypted payload that needs to be processed (base64 encoded)                                                                               |
| `client_dh_public_key`                                                                                                                          | *str*                                                                                                                                           | :heavy_check_mark:                                                                                                                              | Client's public key for Diffie-Hellman key exchange (base64 encoded)                                                                            |
| `model_name`                                                                                                                                    | *str*                                                                                                                                           | :heavy_check_mark:                                                                                                                              | Model name                                                                                                                                      |
| `node_dh_public_key`                                                                                                                            | *str*                                                                                                                                           | :heavy_check_mark:                                                                                                                              | Node's public key for Diffie-Hellman key exchange (base64 encoded)                                                                              |
| `nonce`                                                                                                                                         | *str*                                                                                                                                           | :heavy_check_mark:                                                                                                                              | Cryptographic nonce used for encryption (base64 encoded)                                                                                        |
| `plaintext_body_hash`                                                                                                                           | *str*                                                                                                                                           | :heavy_check_mark:                                                                                                                              | Hash of the original plaintext body for integrity verification (base64 encoded)                                                                 |
| `salt`                                                                                                                                          | *str*                                                                                                                                           | :heavy_check_mark:                                                                                                                              | Salt value used in key derivation (base64 encoded)                                                                                              |
| `stack_small_id`                                                                                                                                | *int*                                                                                                                                           | :heavy_check_mark:                                                                                                                              | Unique identifier for the small stack being used                                                                                                |
| `num_compute_units`                                                                                                                             | *OptionalNullable[int]*                                                                                                                         | :heavy_minus_sign:                                                                                                                              | Number of compute units to be used for the request, for image generations,<br/>as this value is known in advance (the number of pixels to generate) |
| `stream`                                                                                                                                        | *OptionalNullable[bool]*                                                                                                                        | :heavy_minus_sign:                                                                                                                              | Indicates whether this is a streaming request                                                                                                   |
| `retries`                                                                                                                                       | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)                                                                                | :heavy_minus_sign:                                                                                                                              | Configuration to override the default retry behavior of the client.                                                                             |

### Response

**[models.ConfidentialComputeResponse](../../models/confidentialcomputeresponse.md)**

### Errors

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.APIError | 4XX, 5XX        | \*/\*           |