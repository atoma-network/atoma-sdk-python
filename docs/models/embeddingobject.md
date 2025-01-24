# EmbeddingObject

Individual embedding object in the response


## Fields

| Field                                            | Type                                             | Required                                         | Description                                      | Example                                          |
| ------------------------------------------------ | ------------------------------------------------ | ------------------------------------------------ | ------------------------------------------------ | ------------------------------------------------ |
| `embedding`                                      | List[*float*]                                    | :heavy_check_mark:                               | The embedding vector                             | [0.0023064255, -0.009327292]                     |
| `index`                                          | *int*                                            | :heavy_check_mark:                               | Index of the embedding in the list of embeddings | 0                                                |
| `object`                                         | *str*                                            | :heavy_check_mark:                               | The object type, which is always "embedding"     | embedding                                        |