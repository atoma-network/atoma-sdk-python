# CompletionUsage

Represents the completion usage.

This is used to represent the completion usage in the chat completion request.
It can be either a completion usage or a completion chunk usage.


## Fields

| Field                                                                            | Type                                                                             | Required                                                                         | Description                                                                      | Example                                                                          |
| -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `completion_tokens`                                                              | *int*                                                                            | :heavy_check_mark:                                                               | Number of tokens in the completion.                                              | 12                                                                               |
| `prompt_tokens`                                                                  | *int*                                                                            | :heavy_check_mark:                                                               | Number of tokens in the prompt.                                                  | 9                                                                                |
| `prompt_tokens_details`                                                          | [OptionalNullable[models.PromptTokensDetails]](../models/prompttokensdetails.md) | :heavy_minus_sign:                                                               | N/A                                                                              |                                                                                  |
| `total_tokens`                                                                   | *int*                                                                            | :heavy_check_mark:                                                               | Total number of tokens used (prompt + completion).                               | 21                                                                               |