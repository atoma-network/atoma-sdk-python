# NodesModelsRetrieveResponse

The response body for selecting a node's public key for encryption
from a client. The client will use the provided public key to encrypt
the request and send it back to the proxy. The proxy will then route this
request to the selected node.


## Fields

| Field                                                                                    | Type                                                                                     | Required                                                                                 | Description                                                                              |
| ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `node_small_id`                                                                          | *int*                                                                                    | :heavy_check_mark:                                                                       | The node small id for the selected node                                                  |
| `public_key`                                                                             | List[*int*]                                                                              | :heavy_check_mark:                                                                       | The public key for the selected node, base64 encoded                                     |
| `stack_small_id`                                                                         | *int*                                                                                    | :heavy_check_mark:                                                                       | The stack small id to which an available stack entry was acquired, for the selected node |
| `stack_entry_digest`                                                                     | *OptionalNullable[str]*                                                                  | :heavy_minus_sign:                                                                       | Transaction digest for the transaction that acquires the stack entry, if any             |