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
| `stack_small_id`                            | *int*                                       | :heavy_check_mark:                          | The small ID of the stack                   |
| `max_tokens`                                | *OptionalNullable[int]*                     | :heavy_minus_sign:                          | The maximum number of tokens to generate    |
| `stream`                                    | *OptionalNullable[bool]*                    | :heavy_minus_sign:                          | Whether to stream back partial progress     |