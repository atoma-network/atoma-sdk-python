# NodePublicAddressRegistration
(*node_public_address_registration*)

## Overview

Node public address registration

### Available Operations

* [node_public_address_registration](#node_public_address_registration) - Register node

## node_public_address_registration

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

    res = atoma_sdk.node_public_address_registration.node_public_address_registration()

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