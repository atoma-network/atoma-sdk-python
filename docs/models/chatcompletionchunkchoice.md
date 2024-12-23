# ChatCompletionChunkChoice


## Fields

| Field                                                                    | Type                                                                     | Required                                                                 | Description                                                              |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| `delta`                                                                  | [models.ChatCompletionChunkDelta](../models/chatcompletionchunkdelta.md) | :heavy_check_mark:                                                       | N/A                                                                      |
| `index`                                                                  | *int*                                                                    | :heavy_check_mark:                                                       | The index of this choice in the list of choices.                         |
| `finish_reason`                                                          | *OptionalNullable[str]*                                                  | :heavy_minus_sign:                                                       | The reason the chat completion was finished, if applicable.              |