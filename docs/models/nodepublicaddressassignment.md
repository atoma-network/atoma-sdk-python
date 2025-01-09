# NodePublicAddressAssignment

Represents the payload for the node public address registration request.

This struct represents the payload for the node public address registration request.


## Fields

| Field                                        | Type                                         | Required                                     | Description                                  |
| -------------------------------------------- | -------------------------------------------- | -------------------------------------------- | -------------------------------------------- |
| `country`                                    | *str*                                        | :heavy_check_mark:                           | The country of the node                      |
| `node_small_id`                              | *int*                                        | :heavy_check_mark:                           | Unique small integer identifier for the node |
| `public_address`                             | *str*                                        | :heavy_check_mark:                           | The public address of the node               |