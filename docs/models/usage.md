# Usage

Represents usage statistics for a confidential compute request


## Fields

| Field                                                                           | Type                                                                            | Required                                                                        | Description                                                                     |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `prompt_tokens`                                                                 | *int*                                                                           | :heavy_check_mark:                                                              | Number of compute units used                                                    |
| `total_tokens`                                                                  | *int*                                                                           | :heavy_check_mark:                                                              | Number of compute units used                                                    |
| `completion_tokens`                                                             | *OptionalNullable[int]*                                                         | :heavy_minus_sign:                                                              | Number of compute units used<br/>NOTE: This is not used for the embeddings endpoint |
| `completion_tokens_details`                                                     | *Optional[Any]*                                                                 | :heavy_minus_sign:                                                              | Details about the completion tokens                                             |