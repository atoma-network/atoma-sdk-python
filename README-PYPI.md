# Atoma's Python SDK

<img src="https://github.com/atoma-network/atoma-node/blob/main/atoma-assets/atoma-banner.png" alt="Logo"/>

[![Discord](https://img.shields.io/discord/1172593757586214964?label=Discord&logo=discord&logoColor=white)]
[![Twitter](https://img.shields.io/twitter/follow/Atoma_Network?style=social)](https://x.com/Atoma_Network)
[![Documentation](https://img.shields.io/badge/docs-mintify-blue?logo=mintify)](https://docs.atoma.network)
[![License](https://img.shields.io/github/license/atoma-network/atoma-node)](LICENSE)

<div align="left">
    <a href="https://www.speakeasy.com/?utm_source=atoma-sdk&utm_campaign=python"><img src="https://custom-icon-badges.demolab.com/badge/-Built%20By%20Speakeasy-212015?style=for-the-badge&logoColor=FBE331&logo=speakeasy&labelColor=545454" /></a>
</div>

<!-- Start Summary [summary] -->
## Summary


<!-- End Summary [summary] -->

<!-- Start Table of Contents [toc] -->
## Table of Contents
<!-- $toc-max-depth=2 -->
* [Atoma's Python SDK](https://github.com/atoma-network/atoma-sdk-python/blob/master/#atomas-python-sdk)
  * [SDK Installation](https://github.com/atoma-network/atoma-sdk-python/blob/master/#sdk-installation)
  * [IDE Support](https://github.com/atoma-network/atoma-sdk-python/blob/master/#ide-support)
  * [SDK Example Usage](https://github.com/atoma-network/atoma-sdk-python/blob/master/#sdk-example-usage)
  * [Authentication](https://github.com/atoma-network/atoma-sdk-python/blob/master/#authentication)
  * [Available Resources and Operations](https://github.com/atoma-network/atoma-sdk-python/blob/master/#available-resources-and-operations)
  * [Server-sent event streaming](https://github.com/atoma-network/atoma-sdk-python/blob/master/#server-sent-event-streaming)
  * [Retries](https://github.com/atoma-network/atoma-sdk-python/blob/master/#retries)
  * [Error Handling](https://github.com/atoma-network/atoma-sdk-python/blob/master/#error-handling)
  * [Server Selection](https://github.com/atoma-network/atoma-sdk-python/blob/master/#server-selection)
  * [Custom HTTP Client](https://github.com/atoma-network/atoma-sdk-python/blob/master/#custom-http-client)
  * [Debugging](https://github.com/atoma-network/atoma-sdk-python/blob/master/#debugging)
* [Development](https://github.com/atoma-network/atoma-sdk-python/blob/master/#development)
  * [Maturity](https://github.com/atoma-network/atoma-sdk-python/blob/master/#maturity)
  * [Contributions](https://github.com/atoma-network/atoma-sdk-python/blob/master/#contributions)

<!-- End Table of Contents [toc] -->

<!-- Start SDK Installation [installation] -->
## SDK Installation

> [!TIP]
> To finish publishing your SDK to PyPI you must [run your first generation action](https://www.speakeasy.com/docs/github-setup#step-by-step-guide).


The SDK can be installed with either *pip* or *poetry* package managers.

### PIP

*PIP* is the default package installer for Python, enabling easy installation and management of packages from PyPI via the command line.

```bash
pip install git+https://github.com/atoma-network/atoma-sdk-python.git
```

### Poetry

*Poetry* is a modern tool that simplifies dependency management and package publishing by using a single `pyproject.toml` file to handle project metadata and dependencies.

```bash
poetry add git+https://github.com/atoma-network/atoma-sdk-python.git
```
<!-- End SDK Installation [installation] -->

<!-- Start IDE Support [idesupport] -->
## IDE Support

### PyCharm

Generally, the SDK will work well with most IDEs out of the box. However, when using PyCharm, you can enjoy much better integration with Pydantic by installing an additional plugin.

- [PyCharm Pydantic Plugin](https://docs.pydantic.dev/latest/integrations/pycharm/)
<!-- End IDE Support [idesupport] -->

<!-- Start SDK Example Usage [usage] -->
## SDK Example Usage

### Example

```python
# Synchronous Example
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

</br>

The same SDK client can also be used to make asychronous requests by importing asyncio.
```python
# Asynchronous Example
import asyncio
from atoma_sdk import AtomaSDK
import os

async def main():
    async with AtomaSDK(
        bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
    ) as atoma_sdk:

        res = await atoma_sdk.chat.create_async(messages=[
            {
                "content": "Hello! How can you help me today?",
                "role": "user",
            },
        ], model="meta-llama/Llama-3.3-70B-Instruct", frequency_penalty=0, max_tokens=2048, n=1, presence_penalty=0, seed=123, stop=[
            "json([\"stop\", \"halt\"])",
        ], temperature=0.7, top_p=1, user="user-1234")

        # Handle response
        print(res)

asyncio.run(main())
```
<!-- End SDK Example Usage [usage] -->

<!-- Start Authentication [security] -->
## Authentication

### Per-Client Security Schemes

This SDK supports the following security scheme globally:

| Name          | Type | Scheme      | Environment Variable   |
| ------------- | ---- | ----------- | ---------------------- |
| `bearer_auth` | http | HTTP Bearer | `ATOMASDK_BEARER_AUTH` |

To authenticate with the API the `bearer_auth` parameter must be set when initializing the SDK client instance. For example:
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
<!-- End Authentication [security] -->

<!-- Start Available Resources and Operations [operations] -->
## Available Resources and Operations

<details open>
<summary>Available methods</summary>


### [chat](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/chat/README.md)

* [create](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/chat/README.md#create) - Create chat completion
* [create_stream](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/chat/README.md#create_stream)

### [confidential_chat](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/confidentialchat/README.md)

* [create](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/confidentialchat/README.md#create) - Create confidential chat completion
* [create_stream](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/confidentialchat/README.md#create_stream)

### [confidential_embeddings](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/confidentialembeddings/README.md)

* [create](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/confidentialembeddings/README.md#create) - Create confidential embeddings

### [confidential_images](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/confidentialimages/README.md)

* [generate](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/confidentialimages/README.md#generate) - Create confidential image

### [embeddings](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/embeddings/README.md)

* [create](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/embeddings/README.md#create) - Create embeddings

### [health](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/health/README.md)

* [health](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/health/README.md#health) - Health

### [images](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/images/README.md)

* [generate](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/images/README.md#generate) - Create image

### [models](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/models/README.md)

* [models_list](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/models/README.md#models_list) - List models

### [nodes](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/nodes/README.md)

* [nodes_create](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/nodes/README.md#nodes_create) - Create node
* [nodes_create_lock](https://github.com/atoma-network/atoma-sdk-python/blob/master/docs/sdks/nodes/README.md#nodes_create_lock) - Create a node lock for confidential compute

</details>
<!-- End Available Resources and Operations [operations] -->

<!-- Start Server-sent event streaming [eventstream] -->
## Server-sent event streaming

[Server-sent events][mdn-sse] are used to stream content from certain
operations. These operations will expose the stream as [Generator][generator] that
can be consumed using a simple `for` loop. The loop will
terminate when the server no longer has any events to send and closes the
underlying connection.  

The stream is also a [Context Manager][context-manager] and can be used with the `with` statement and will close the
underlying connection when the context is exited.

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

[mdn-sse]: https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events
[generator]: https://book.pythontips.com/en/latest/generators.html
[context-manager]: https://book.pythontips.com/en/latest/context_managers.html
<!-- End Server-sent event streaming [eventstream] -->

<!-- Start Retries [retries] -->
## Retries

Some of the endpoints in this SDK support retries. If you use the SDK without any configuration, it will fall back to the default retry strategy provided by the API. However, the default retry strategy can be overridden on a per-operation basis, or across the entire SDK.

To change the default retry strategy for a single API call, simply provide a `RetryConfig` object to the call:
```python
from atoma_sdk import AtomaSDK
from atoma_sdk.utils import BackoffStrategy, RetryConfig
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
    ], temperature=0.7, top_p=1, user="user-1234",
        RetryConfig("backoff", BackoffStrategy(1, 50, 1.1, 100), False))

    # Handle response
    print(res)

```

If you'd like to override the default retry strategy for all operations that support retries, you can use the `retry_config` optional parameter when initializing the SDK:
```python
from atoma_sdk import AtomaSDK
from atoma_sdk.utils import BackoffStrategy, RetryConfig
import os

with AtomaSDK(
    retry_config=RetryConfig("backoff", BackoffStrategy(1, 50, 1.1, 100), False),
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
<!-- End Retries [retries] -->

<!-- Start Error Handling [errors] -->
## Error Handling

Handling errors in this SDK should largely match your expectations. All operations return a response object or raise an exception.

By default, an API error will raise a models.APIError exception, which has the following properties:

| Property        | Type             | Description           |
|-----------------|------------------|-----------------------|
| `.status_code`  | *int*            | The HTTP status code  |
| `.message`      | *str*            | The error message     |
| `.raw_response` | *httpx.Response* | The raw HTTP response |
| `.body`         | *str*            | The response content  |

When custom error responses are specified for an operation, the SDK may also raise their associated exceptions. You can refer to respective *Errors* tables in SDK docs for more details on possible exception types for each operation. For example, the `create_async` method may raise the following exceptions:

| Error Type      | Status Code | Content Type |
| --------------- | ----------- | ------------ |
| models.APIError | 4XX, 5XX    | \*/\*        |

### Example

```python
from atoma_sdk import AtomaSDK, models
import os

with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as atoma_sdk:
    res = None
    try:

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

    except models.APIError as e:
        # handle exception
        raise(e)
```
<!-- End Error Handling [errors] -->

<!-- Start Server Selection [server] -->
## Server Selection

### Override Server URL Per-Client

The default server can also be overridden globally by passing a URL to the `server_url: str` optional parameter when initializing the SDK client instance. For example:
```python
from atoma_sdk import AtomaSDK
import os

with AtomaSDK(
    server_url="https://api.atoma.network",
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
<!-- End Server Selection [server] -->

<!-- Start Custom HTTP Client [http-client] -->
## Custom HTTP Client

The Python SDK makes API calls using the [httpx](https://www.python-httpx.org/) HTTP library.  In order to provide a convenient way to configure timeouts, cookies, proxies, custom headers, and other low-level configuration, you can initialize the SDK client with your own HTTP client instance.
Depending on whether you are using the sync or async version of the SDK, you can pass an instance of `HttpClient` or `AsyncHttpClient` respectively, which are Protocol's ensuring that the client has the necessary methods to make API calls.
This allows you to wrap the client with your own custom logic, such as adding custom headers, logging, or error handling, or you can just pass an instance of `httpx.Client` or `httpx.AsyncClient` directly.

For example, you could specify a header for every request that this sdk makes as follows:
```python
from atoma_sdk import AtomaSDK
import httpx

http_client = httpx.Client(headers={"x-custom-header": "someValue"})
s = AtomaSDK(client=http_client)
```

or you could wrap the client with your own custom logic:
```python
from atoma_sdk import AtomaSDK
from atoma_sdk.httpclient import AsyncHttpClient
import httpx

class CustomClient(AsyncHttpClient):
    client: AsyncHttpClient

    def __init__(self, client: AsyncHttpClient):
        self.client = client

    async def send(
        self,
        request: httpx.Request,
        *,
        stream: bool = False,
        auth: Union[
            httpx._types.AuthTypes, httpx._client.UseClientDefault, None
        ] = httpx.USE_CLIENT_DEFAULT,
        follow_redirects: Union[
            bool, httpx._client.UseClientDefault
        ] = httpx.USE_CLIENT_DEFAULT,
    ) -> httpx.Response:
        request.headers["Client-Level-Header"] = "added by client"

        return await self.client.send(
            request, stream=stream, auth=auth, follow_redirects=follow_redirects
        )

    def build_request(
        self,
        method: str,
        url: httpx._types.URLTypes,
        *,
        content: Optional[httpx._types.RequestContent] = None,
        data: Optional[httpx._types.RequestData] = None,
        files: Optional[httpx._types.RequestFiles] = None,
        json: Optional[Any] = None,
        params: Optional[httpx._types.QueryParamTypes] = None,
        headers: Optional[httpx._types.HeaderTypes] = None,
        cookies: Optional[httpx._types.CookieTypes] = None,
        timeout: Union[
            httpx._types.TimeoutTypes, httpx._client.UseClientDefault
        ] = httpx.USE_CLIENT_DEFAULT,
        extensions: Optional[httpx._types.RequestExtensions] = None,
    ) -> httpx.Request:
        return self.client.build_request(
            method,
            url,
            content=content,
            data=data,
            files=files,
            json=json,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            extensions=extensions,
        )

s = AtomaSDK(async_client=CustomClient(httpx.AsyncClient()))
```
<!-- End Custom HTTP Client [http-client] -->

<!-- Start Debugging [debug] -->
## Debugging

You can setup your SDK to emit debug logs for SDK requests and responses.

You can pass your own logger class directly into your SDK.
```python
from atoma_sdk import AtomaSDK
import logging

logging.basicConfig(level=logging.DEBUG)
s = AtomaSDK(debug_logger=logging.getLogger("atoma_sdk"))
```

You can also enable a default debug logger by setting an environment variable `ATOMASDK_DEBUG` to true.
<!-- End Debugging [debug] -->

<!-- Placeholder for Future Speakeasy SDK Sections -->

# Development

## Maturity

This SDK is in beta, and there may be breaking changes between versions without a major version update. Therefore, we recommend pinning usage
to a specific package version. This way, you can install the same version each time without breaking changes unless you are intentionally
looking for the latest version.

## Contributions

While we value open-source contributions to this SDK, this library is generated programmatically. Any manual changes added to internal files will be overwritten on the next generation.
We look forward to hearing your feedback. Feel free to open a PR or an issue with a proof of concept and we'll do our best to include it in a future release.

### SDK Created by [Speakeasy](https://www.speakeasy.com/?utm_source=atoma-sdk&utm_campaign=python)
