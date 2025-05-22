# NodesCreateLockRequest

Request body for creating a node lock


## Fields

| Field                                                                                             | Type                                                                                              | Required                                                                                          | Description                                                                                       |
| ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `max_num_tokens`                                                                                  | *OptionalNullable[int]*                                                                           | :heavy_minus_sign:                                                                                | The number of tokens to be processed for confidential compute<br/>(including input and output tokens) |
| `model`                                                                                           | *str*                                                                                             | :heavy_check_mark:                                                                                | The model to lock a node for                                                                      |
| `timeout`                                                                                         | *OptionalNullable[int]*                                                                           | :heavy_minus_sign:                                                                                | An optional timeout period for the locked compute units, in seconds                               |