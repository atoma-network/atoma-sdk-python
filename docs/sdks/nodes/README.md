# Nodes
(*nodes*)

## Overview

Nodes Management

### Available Operations

* [nodes_create](#nodes_create) - Create node
* [nodes_create_lock](#nodes_create_lock) - Create a node lock for confidential compute

## nodes_create

This endpoint allows nodes to register or update their public address in the system.
When a node comes online or changes its address, it can use this endpoint to ensure
the system has its current address for routing requests.

## Errors

Returns various `AtomaProxyError` variants:
* `MissingHeader` - If the signature header is missing
* `InvalidHeader` - If the signature header is malformed
* `InvalidBody` - If:
  - The request body cannot be read
  - The signature is invalid
  - The body cannot be parsed
  - The sui address doesn't match the signature
* `InternalError` - If:
  - The state manager channel is closed
  - The registration event cannot be sent
  - Node Sui address lookup fails

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os

with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as atoma_sdk:

    res = atoma_sdk.nodes.nodes_create(data={
        "country": "Andorra",
        "node_small_id": 3665,
        "public_address": "<value>",
    }, signature="<value>")

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                                                                                                                      | Type                                                                                                                                                           | Required                                                                                                                                                       | Description                                                                                                                                                    |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `data`                                                                                                                                                         | [models.NodePublicAddressAssignment](../../models/nodepublicaddressassignment.md)                                                                              | :heavy_check_mark:                                                                                                                                             | Represents the payload for the node public address registration request.<br/><br/>This struct represents the payload for the node public address registration request. |
| `signature`                                                                                                                                                    | *str*                                                                                                                                                          | :heavy_check_mark:                                                                                                                                             | The signature of the data base 64 encoded                                                                                                                      |
| `retries`                                                                                                                                                      | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)                                                                                               | :heavy_minus_sign:                                                                                                                                             | Configuration to override the default retry behavior of the client.                                                                                            |

### Response

**[models.NodesCreateResponse](../../models/nodescreateresponse.md)**

### Errors

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.APIError | 4XX, 5XX        | \*/\*           |

## nodes_create_lock

This endpoint attempts to find a suitable node and retrieve its public key for encryption
through a two-step process:

1. First, it tries to select an existing node with a public key directly.
2. If no node is immediately available, it falls back to finding the cheapest compatible node
   and acquiring a new stack entry for it.

This endpoint is specifically designed for confidential compute scenarios where
requests need to be encrypted before being processed by nodes.

## Errors
  - `INTERNAL_SERVER_ERROR` - Communication errors or missing node public keys
  - `SERVICE_UNAVAILABLE` - No nodes available for confidential compute

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os

with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as atoma_sdk:

    res = atoma_sdk.nodes.nodes_create_lock(model="Focus")

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                           | Type                                                                | Required                                                            | Description                                                         |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `model`                                                             | *str*                                                               | :heavy_check_mark:                                                  | The model to lock a node for                                        |
| `retries`                                                           | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)    | :heavy_minus_sign:                                                  | Configuration to override the default retry behavior of the client. |

### Response

**[models.NodesCreateLockResponse](../../models/nodescreatelockresponse.md)**

### Errors

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.APIError | 4XX, 5XX        | \*/\*           |