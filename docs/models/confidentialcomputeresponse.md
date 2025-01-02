# ConfidentialComputeResponse

Represents a response from a confidential compute request


## Fields

| Field                                                | Type                                                 | Required                                             | Description                                          |
| ---------------------------------------------------- | ---------------------------------------------------- | ---------------------------------------------------- | ---------------------------------------------------- |
| `ciphertext`                                         | *str*                                                | :heavy_check_mark:                                   | Encrypted response body (base64 encoded)             |
| `nonce`                                              | *str*                                                | :heavy_check_mark:                                   | Nonce used for encryption (base64 encoded)           |
| `response_hash`                                      | *OptionalNullable[str]*                              | :heavy_minus_sign:                                   | Hash of the response body (base64 encoded)           |
| `signature`                                          | *OptionalNullable[str]*                              | :heavy_minus_sign:                                   | Signature of the response body (base64 encoded)      |
| `usage`                                              | [OptionalNullable[models.Usage]](../models/usage.md) | :heavy_minus_sign:                                   | N/A                                                  |