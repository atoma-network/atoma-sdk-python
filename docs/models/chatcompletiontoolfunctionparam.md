# ChatCompletionToolFunctionParam

A function that can be used in a chat completion.


## Fields

| Field                                                        | Type                                                         | Required                                                     | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| `description`                                                | *OptionalNullable[str]*                                      | :heavy_minus_sign:                                           | The description of the function.                             |
| `name`                                                       | *str*                                                        | :heavy_check_mark:                                           | The name of the function.                                    |
| `parameters`                                                 | Dict[str, *Any*]                                             | :heavy_minus_sign:                                           | The parameters of the function.                              |
| `strict`                                                     | *OptionalNullable[bool]*                                     | :heavy_minus_sign:                                           | Whether to strictly validate the parameters of the function. |