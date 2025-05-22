# Tool

The role of the messages author, in this case tool.


## Fields

| Field                                                                  | Type                                                                   | Required                                                               | Description                                                            |
| ---------------------------------------------------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `content`                                                              | [OptionalNullable[models.MessageContent]](../models/messagecontent.md) | :heavy_minus_sign:                                                     | N/A                                                                    |
| `role`                                                                 | [models.RoleTool](../models/roletool.md)                               | :heavy_check_mark:                                                     | N/A                                                                    |
| `tool_call_id`                                                         | *Optional[str]*                                                        | :heavy_minus_sign:                                                     | Tool call that this message is responding to.                          |