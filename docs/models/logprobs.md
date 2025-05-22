# LogProbs


## Fields

| Field                                 | Type                                  | Required                              | Description                           | Example                               |
| ------------------------------------- | ------------------------------------- | ------------------------------------- | ------------------------------------- | ------------------------------------- |
| `text_offset`                         | List[*int*]                           | :heavy_check_mark:                    | The text offset of the tokens         | [<br/>0,<br/>10<br/>]                 |
| `token_logprobs`                      | List[*float*]                         | :heavy_check_mark:                    | The log probabilities of the tokens   | [<br/>0.5,<br/>-0.5<br/>]             |
| `tokens`                              | List[*str*]                           | :heavy_check_mark:                    | The tokens                            | [<br/>"Hello ",<br/>"world"<br/>]     |
| `top_logprobs`                        | List[Dict[str, *float*]]              | :heavy_check_mark:                    | The top log probabilities             | [<br/>{<br/>"Hello ": -0.2,<br/>"world": -0.8<br/>}<br/>] |