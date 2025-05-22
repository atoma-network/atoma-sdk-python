# ConfidentialImages
(*confidential_images*)

## Overview

### Available Operations

* [generate](#generate) - Create confidential image

## generate

This handler processes image generation requests in a confidential manner, providing additional
encryption and security measures for sensitive data processing. It supports both streaming and
non-streaming responses while maintaining data confidentiality through AEAD encryption and TEE hardware,
for full private AI compute.

### Example Usage

```python
from atoma_sdk import AtomaSDK
import os


with AtomaSDK(
    bearer_auth=os.getenv("ATOMASDK_BEARER_AUTH", ""),
) as as_client:

    res = as_client.confidential_images.generate(ciphertext="<value>", client_dh_public_key="<value>", model_name="<value>", node_dh_public_key="<value>", nonce="<value>", plaintext_body_hash="<value>", salt="<value>", stack_small_id=740198)

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