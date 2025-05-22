# ResponseFormat

The format to return the response in.

This is used to represent the format to return the response in in the chat completion request.
It can be either text, json_object, or json_schema.


## Fields

| Field                                                                                      | Type                                                                                       | Required                                                                                   | Description                                                                                |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| `json_schema`                                                                              | [OptionalNullable[models.JSONSchemaResponseFormat]](../models/jsonschemaresponseformat.md) | :heavy_minus_sign:                                                                         | N/A                                                                                        |
| `type`                                                                                     | [models.ResponseFormatType](../models/responseformattype.md)                               | :heavy_check_mark:                                                                         | The format to return the response in.                                                      |