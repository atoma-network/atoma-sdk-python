# Chat
(*chat*)

## Overview

OpenAI's API chat completions v1 endpoint

### Available Operations

* [create](#create) - Create chat completion
* [create_stream](#create_stream)

## create

This function processes chat completion requests by determining whether to use streaming
or non-streaming response handling based on the request payload. For streaming requests,
it configures additional options to track token usage.

## Returns

Returns a Response containing either:
- A streaming SSE connection for real-time completions
- A single JSON response for non-streaming completions

## Errors

Returns an error status code if:
- The request processing fails
- The streaming/non-streaming handlers encounter errors
- The underlying inference service returns an error

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os

with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as atoma_sdk:

    res = atoma_sdk.chat.create(messages=[
        {
            "content": "Hello! How can you help me today?",
            "role": "user",
        },
    ], model="meta-llama/Llama-3.3-70B-Instruct", frequency_penalty=0, max_tokens=2048, n=1, presence_penalty=0, seed=123, stop=[
        "json([\"stop\", \"halt\"])",
    ], temperature=0.7, top_p=1, user="user-1234")

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                                                                             | Type                                                                                                                  | Required                                                                                                              | Description                                                                                                           | Example                                                                                                               |
| --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `messages`                                                                                                            | List[[models.ChatCompletionMessage](../../models/chatcompletionmessage.md)]                                           | :heavy_check_mark:                                                                                                    | A list of messages comprising the conversation so far                                                                 |                                                                                                                       |
| `model`                                                                                                               | *str*                                                                                                                 | :heavy_check_mark:                                                                                                    | ID of the model to use                                                                                                | meta-llama/Llama-3.3-70B-Instruct                                                                                     |
| `frequency_penalty`                                                                                                   | *OptionalNullable[float]*                                                                                             | :heavy_minus_sign:                                                                                                    | Number between -2.0 and 2.0. Positive values penalize new tokens based on their<br/>existing frequency in the text so far | 0                                                                                                                     |
| `function_call`                                                                                                       | *Optional[Any]*                                                                                                       | :heavy_minus_sign:                                                                                                    | Controls how the model responds to function calls                                                                     |                                                                                                                       |
| `functions`                                                                                                           | List[*Any*]                                                                                                           | :heavy_minus_sign:                                                                                                    | A list of functions the model may generate JSON inputs for                                                            |                                                                                                                       |
| `logit_bias`                                                                                                          | Dict[str, *float*]                                                                                                    | :heavy_minus_sign:                                                                                                    | Modify the likelihood of specified tokens appearing in the completion                                                 |                                                                                                                       |
| `max_tokens`                                                                                                          | *OptionalNullable[int]*                                                                                               | :heavy_minus_sign:                                                                                                    | The maximum number of tokens to generate in the chat completion                                                       | 2048                                                                                                                  |
| `n`                                                                                                                   | *OptionalNullable[int]*                                                                                               | :heavy_minus_sign:                                                                                                    | How many chat completion choices to generate for each input message                                                   | 1                                                                                                                     |
| `presence_penalty`                                                                                                    | *OptionalNullable[float]*                                                                                             | :heavy_minus_sign:                                                                                                    | Number between -2.0 and 2.0. Positive values penalize new tokens based on<br/>whether they appear in the text so far  | 0                                                                                                                     |
| `response_format`                                                                                                     | *Optional[Any]*                                                                                                       | :heavy_minus_sign:                                                                                                    | The format to return the response in                                                                                  |                                                                                                                       |
| `seed`                                                                                                                | *OptionalNullable[int]*                                                                                               | :heavy_minus_sign:                                                                                                    | If specified, our system will make a best effort to sample deterministically                                          | 123                                                                                                                   |
| `stop`                                                                                                                | List[*str*]                                                                                                           | :heavy_minus_sign:                                                                                                    | Up to 4 sequences where the API will stop generating further tokens                                                   | json(["stop", "halt"])                                                                                                |
| `stream`                                                                                                              | *OptionalNullable[bool]*                                                                                              | :heavy_minus_sign:                                                                                                    | Whether to stream back partial progress. Must be false for this request type.                                         |                                                                                                                       |
| `temperature`                                                                                                         | *OptionalNullable[float]*                                                                                             | :heavy_minus_sign:                                                                                                    | What sampling temperature to use, between 0 and 2                                                                     | 0.7                                                                                                                   |
| `tool_choice`                                                                                                         | *Optional[Any]*                                                                                                       | :heavy_minus_sign:                                                                                                    | Controls which (if any) tool the model should use                                                                     |                                                                                                                       |
| `tools`                                                                                                               | List[*Any*]                                                                                                           | :heavy_minus_sign:                                                                                                    | A list of tools the model may call                                                                                    |                                                                                                                       |
| `top_p`                                                                                                               | *OptionalNullable[float]*                                                                                             | :heavy_minus_sign:                                                                                                    | An alternative to sampling with temperature                                                                           | 1                                                                                                                     |
| `user`                                                                                                                | *OptionalNullable[str]*                                                                                               | :heavy_minus_sign:                                                                                                    | A unique identifier representing your end-user                                                                        | user-1234                                                                                                             |
| `retries`                                                                                                             | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)                                                      | :heavy_minus_sign:                                                                                                    | Configuration to override the default retry behavior of the client.                                                   |                                                                                                                       |

### Response

**[models.ChatCompletionResponse](../../models/chatcompletionresponse.md)**

### Errors

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.APIError | 4XX, 5XX        | \*/\*           |

## create_stream

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os

with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as atoma_sdk:

    res = atoma_sdk.chat.create_stream(messages=[
        {
            "content": "Hello! How can you help me today?",
            "role": "user",
            "name": "john_doe",
        },
    ], model="meta-llama/Llama-3.3-70B-Instruct", frequency_penalty=0, max_tokens=2048, n=1, presence_penalty=0, seed=123, stop=[
        "json([\"stop\", \"halt\"])",
    ], temperature=0.7, top_p=1, user="user-1234")

    with res as event_stream:
        for event in event_stream:
            # handle event
            print(event, flush=True)

```

### Parameters

| Parameter                                                                                                             | Type                                                                                                                  | Required                                                                                                              | Description                                                                                                           | Example                                                                                                               |
| --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `messages`                                                                                                            | List[[models.ChatCompletionMessage](../../models/chatcompletionmessage.md)]                                           | :heavy_check_mark:                                                                                                    | A list of messages comprising the conversation so far                                                                 |                                                                                                                       |
| `model`                                                                                                               | *str*                                                                                                                 | :heavy_check_mark:                                                                                                    | ID of the model to use                                                                                                | meta-llama/Llama-3.3-70B-Instruct                                                                                     |
| `frequency_penalty`                                                                                                   | *OptionalNullable[float]*                                                                                             | :heavy_minus_sign:                                                                                                    | Number between -2.0 and 2.0. Positive values penalize new tokens based on their<br/>existing frequency in the text so far | 0                                                                                                                     |
| `function_call`                                                                                                       | *Optional[Any]*                                                                                                       | :heavy_minus_sign:                                                                                                    | Controls how the model responds to function calls                                                                     |                                                                                                                       |
| `functions`                                                                                                           | List[*Any*]                                                                                                           | :heavy_minus_sign:                                                                                                    | A list of functions the model may generate JSON inputs for                                                            |                                                                                                                       |
| `logit_bias`                                                                                                          | Dict[str, *float*]                                                                                                    | :heavy_minus_sign:                                                                                                    | Modify the likelihood of specified tokens appearing in the completion                                                 |                                                                                                                       |
| `max_tokens`                                                                                                          | *OptionalNullable[int]*                                                                                               | :heavy_minus_sign:                                                                                                    | The maximum number of tokens to generate in the chat completion                                                       | 2048                                                                                                                  |
| `n`                                                                                                                   | *OptionalNullable[int]*                                                                                               | :heavy_minus_sign:                                                                                                    | How many chat completion choices to generate for each input message                                                   | 1                                                                                                                     |
| `presence_penalty`                                                                                                    | *OptionalNullable[float]*                                                                                             | :heavy_minus_sign:                                                                                                    | Number between -2.0 and 2.0. Positive values penalize new tokens based on<br/>whether they appear in the text so far  | 0                                                                                                                     |
| `response_format`                                                                                                     | *Optional[Any]*                                                                                                       | :heavy_minus_sign:                                                                                                    | The format to return the response in                                                                                  |                                                                                                                       |
| `seed`                                                                                                                | *OptionalNullable[int]*                                                                                               | :heavy_minus_sign:                                                                                                    | If specified, our system will make a best effort to sample deterministically                                          | 123                                                                                                                   |
| `stop`                                                                                                                | List[*str*]                                                                                                           | :heavy_minus_sign:                                                                                                    | Up to 4 sequences where the API will stop generating further tokens                                                   | json(["stop", "halt"])                                                                                                |
| `stream`                                                                                                              | *Optional[bool]*                                                                                                      | :heavy_minus_sign:                                                                                                    | Whether to stream back partial progress. Must be true for this request type.                                          |                                                                                                                       |
| `temperature`                                                                                                         | *OptionalNullable[float]*                                                                                             | :heavy_minus_sign:                                                                                                    | What sampling temperature to use, between 0 and 2                                                                     | 0.7                                                                                                                   |
| `tool_choice`                                                                                                         | *Optional[Any]*                                                                                                       | :heavy_minus_sign:                                                                                                    | Controls which (if any) tool the model should use                                                                     |                                                                                                                       |
| `tools`                                                                                                               | List[*Any*]                                                                                                           | :heavy_minus_sign:                                                                                                    | A list of tools the model may call                                                                                    |                                                                                                                       |
| `top_p`                                                                                                               | *OptionalNullable[float]*                                                                                             | :heavy_minus_sign:                                                                                                    | An alternative to sampling with temperature                                                                           | 1                                                                                                                     |
| `user`                                                                                                                | *OptionalNullable[str]*                                                                                               | :heavy_minus_sign:                                                                                                    | A unique identifier representing your end-user                                                                        | user-1234                                                                                                             |
| `retries`                                                                                                             | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)                                                      | :heavy_minus_sign:                                                                                                    | Configuration to override the default retry behavior of the client.                                                   |                                                                                                                       |

### Response

**[Union[eventstreaming.EventStream[models.ChatCompletionStreamResponse], eventstreaming.EventStreamAsync[models.ChatCompletionStreamResponse]]](../../models/.md)**

### Errors

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.APIError | 4XX, 5XX        | \*/\*           |