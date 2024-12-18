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

    res = atoma_sdk.confidential_chat.create(messages=[
        {
            "content": "<value>",
            "role": "<value>",
        },
    ], model="LeBaron")

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                                                                             | Type                                                                                                                  | Required                                                                                                              | Description                                                                                                           |
| --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `messages`                                                                                                            | List[[models.ChatCompletionMessage](../../models/chatcompletionmessage.md)]                                           | :heavy_check_mark:                                                                                                    | A list of messages comprising the conversation so far                                                                 |
| `model`                                                                                                               | *str*                                                                                                                 | :heavy_check_mark:                                                                                                    | ID of the model to use                                                                                                |
| `frequency_penalty`                                                                                                   | *OptionalNullable[float]*                                                                                             | :heavy_minus_sign:                                                                                                    | Number between -2.0 and 2.0. Positive values penalize new tokens based on their<br/>existing frequency in the text so far |
| `function_call`                                                                                                       | *Optional[Any]*                                                                                                       | :heavy_minus_sign:                                                                                                    | Controls how the model responds to function calls                                                                     |
| `functions`                                                                                                           | List[*Any*]                                                                                                           | :heavy_minus_sign:                                                                                                    | A list of functions the model may generate JSON inputs for                                                            |
| `logit_bias`                                                                                                          | Dict[str, *float*]                                                                                                    | :heavy_minus_sign:                                                                                                    | Modify the likelihood of specified tokens appearing in the completion                                                 |
| `max_tokens`                                                                                                          | *OptionalNullable[int]*                                                                                               | :heavy_minus_sign:                                                                                                    | The maximum number of tokens to generate in the chat completion                                                       |
| `n`                                                                                                                   | *OptionalNullable[int]*                                                                                               | :heavy_minus_sign:                                                                                                    | How many chat completion choices to generate for each input message                                                   |
| `presence_penalty`                                                                                                    | *OptionalNullable[float]*                                                                                             | :heavy_minus_sign:                                                                                                    | Number between -2.0 and 2.0. Positive values penalize new tokens based on<br/>whether they appear in the text so far  |
| `response_format`                                                                                                     | *Optional[Any]*                                                                                                       | :heavy_minus_sign:                                                                                                    | The format to return the response in                                                                                  |
| `seed`                                                                                                                | *OptionalNullable[int]*                                                                                               | :heavy_minus_sign:                                                                                                    | If specified, our system will make a best effort to sample deterministically                                          |
| `stop`                                                                                                                | List[*str*]                                                                                                           | :heavy_minus_sign:                                                                                                    | Up to 4 sequences where the API will stop generating further tokens                                                   |
| `stream`                                                                                                              | *OptionalNullable[bool]*                                                                                              | :heavy_minus_sign:                                                                                                    | Whether to stream back partial progress                                                                               |
| `temperature`                                                                                                         | *OptionalNullable[float]*                                                                                             | :heavy_minus_sign:                                                                                                    | What sampling temperature to use, between 0 and 2                                                                     |
| `tool_choice`                                                                                                         | *Optional[Any]*                                                                                                       | :heavy_minus_sign:                                                                                                    | Controls which (if any) tool the model should use                                                                     |
| `tools`                                                                                                               | List[*Any*]                                                                                                           | :heavy_minus_sign:                                                                                                    | A list of tools the model may call                                                                                    |
| `top_p`                                                                                                               | *OptionalNullable[float]*                                                                                             | :heavy_minus_sign:                                                                                                    | An alternative to sampling with temperature                                                                           |
| `user`                                                                                                                | *OptionalNullable[str]*                                                                                               | :heavy_minus_sign:                                                                                                    | A unique identifier representing your end-user                                                                        |
| `retries`                                                                                                             | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)                                                      | :heavy_minus_sign:                                                                                                    | Configuration to override the default retry behavior of the client.                                                   |

### Response

**[models.ChatCompletionResponse](../../models/chatcompletionresponse.md)**

### Errors

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.APIError | 4XX, 5XX        | \*/\*           |