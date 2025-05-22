# ChatCompletionNamedToolChoiceParam

A named tool choice that can be used in a chat completion.

This is used to represent the named tool choice in the chat completion request.


## Fields

| Field                                                                                                                                 | Type                                                                                                                                  | Required                                                                                                                              | Description                                                                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `function`                                                                                                                            | [models.ChatCompletionNamedFunction](../models/chatcompletionnamedfunction.md)                                                        | :heavy_check_mark:                                                                                                                    | A named function that can be used in a chat completion.<br/><br/>This is used to represent the named function in the chat completion request. |
| `type`                                                                                                                                | *str*                                                                                                                                 | :heavy_check_mark:                                                                                                                    | The type of the tool choice.                                                                                                          |