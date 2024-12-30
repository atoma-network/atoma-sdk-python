# ConfidentialChatCompletionRequest

Request format for confidential chat completions


## Fields

| Field                                       | Type                                        | Required                                    | Description                                 |
| ------------------------------------------- | ------------------------------------------- | ------------------------------------------- | ------------------------------------------- |
| `ciphertext`                                | *str*                                       | :heavy_check_mark:                          | The encrypted CreateChatCompletionRequest   |
| `client_dh_public_key`                      | *str*                                       | :heavy_check_mark:                          | Client's DH public key for key exchange     |
| `nonce`                                     | *str*                                       | :heavy_check_mark:                          | Nonce used for encryption                   |
| `plaintext_body_hash`                       | *str*                                       | :heavy_check_mark:                          | Hash of the plaintext body for verification |
| `salt`                                      | *str*                                       | :heavy_check_mark:                          | Salt used for encryption                    |