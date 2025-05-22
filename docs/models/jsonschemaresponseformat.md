# JSONSchemaResponseFormat

The format to return the response in.

This is used to represent the format to return the response in in the chat completion request.
It can be either text, json_object, or json_schema.


## Fields

| Field                                         | Type                                          | Required                                      | Description                                   |
| --------------------------------------------- | --------------------------------------------- | --------------------------------------------- | --------------------------------------------- |
| `description`                                 | *OptionalNullable[str]*                       | :heavy_minus_sign:                            | The description of the response format.       |
| `name`                                        | *str*                                         | :heavy_check_mark:                            | The name of the response format.              |
| `schema_`                                     | *Optional[Any]*                               | :heavy_minus_sign:                            | The JSON schema of the response format.       |
| `strict`                                      | *OptionalNullable[bool]*                      | :heavy_minus_sign:                            | Whether to strictly validate the JSON schema. |