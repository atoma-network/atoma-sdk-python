# ChatCompletionChunkDelta


## Fields

| Field                                                     | Type                                                      | Required                                                  | Description                                               |
| --------------------------------------------------------- | --------------------------------------------------------- | --------------------------------------------------------- | --------------------------------------------------------- |
| `content`                                                 | *OptionalNullable[str]*                                   | :heavy_minus_sign:                                        | The content of the message, if present in this chunk.     |
| `function_call`                                           | *Optional[Any]*                                           | :heavy_minus_sign:                                        | The function call information, if present in this chunk.  |
| `role`                                                    | *OptionalNullable[str]*                                   | :heavy_minus_sign:                                        | The role of the message author, if present in this chunk. |
| `tool_calls`                                              | List[*Any*]                                               | :heavy_minus_sign:                                        | The tool calls information, if present in this chunk.     |