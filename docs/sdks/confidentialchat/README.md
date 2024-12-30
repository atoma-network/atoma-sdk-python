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
* A `StatusCode` error if the request processing fails

# Errors

Returns `StatusCode::BAD_REQUEST` if:
* The 'stream' field is missing or invalid in the payload

Returns `StatusCode::INTERNAL_SERVER_ERROR` if:
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

    res = atoma_sdk.confidential_chat.create(ciphertext="<value>", client_dh_public_key="<value>", nonce="<value>", plaintext_body_hash="<value>", salt="<value>")

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                           | Type                                                                | Required                                                            | Description                                                         |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `ciphertext`                                                        | *str*                                                               | :heavy_check_mark:                                                  | The encrypted CreateChatCompletionRequest                           |
| `client_dh_public_key`                                              | *str*                                                               | :heavy_check_mark:                                                  | Client's DH public key for key exchange                             |
| `nonce`                                                             | *str*                                                               | :heavy_check_mark:                                                  | Nonce used for encryption                                           |
| `plaintext_body_hash`                                               | *str*                                                               | :heavy_check_mark:                                                  | Hash of the plaintext body for verification                         |
| `salt`                                                              | *str*                                                               | :heavy_check_mark:                                                  | Salt used for encryption                                            |
| `retries`                                                           | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)    | :heavy_minus_sign:                                                  | Configuration to override the default retry behavior of the client. |

### Response

**[models.ConfidentialChatCompletionResponse](../../models/confidentialchatcompletionresponse.md)**

### Errors

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.APIError | 4XX, 5XX        | \*/\*           |