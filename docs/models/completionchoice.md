# CompletionChoice

A completion choice response


## Fields

| Field                                                      | Type                                                       | Required                                                   | Description                                                | Example                                                    |
| ---------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------- |
| `finish_reason`                                            | *str*                                                      | :heavy_check_mark:                                         | The reason the model stopped generating tokens             | stop                                                       |
| `index`                                                    | *int*                                                      | :heavy_check_mark:                                         | The index of the choice in the list of choices             | 0                                                          |
| `logprobs`                                                 | [OptionalNullable[models.LogProbs]](../models/logprobs.md) | :heavy_minus_sign:                                         | N/A                                                        |                                                            |
| `text`                                                     | *str*                                                      | :heavy_check_mark:                                         | The generated text                                         | This is a test                                             |