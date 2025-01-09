# Model

Individual model object in the response


## Fields

| Field                                                   | Type                                                    | Required                                                | Description                                             |
| ------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------- |
| `created`                                               | *int*                                                   | :heavy_check_mark:                                      | Unix timestamp (in seconds) when this model was created |
| `id`                                                    | *str*                                                   | :heavy_check_mark:                                      | The model identifier                                    |
| `object`                                                | *str*                                                   | :heavy_check_mark:                                      | The object type, which is always "model"                |
| `owned_by`                                              | *str*                                                   | :heavy_check_mark:                                      | Organization that owns the model                        |