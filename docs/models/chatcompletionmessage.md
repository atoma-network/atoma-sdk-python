# ChatCompletionMessage

A message that is part of a conversation which is based on the role
of the author of the message.

This is used to represent the message in the chat completion request.
It can be either a system message, a user message, an assistant message, or a tool message.


## Supported Types

### `models.System`

```python
value: models.System = /* values here */
```

### `models.User`

```python
value: models.User = /* values here */
```

### `models.Assistant`

```python
value: models.Assistant = /* values here */
```

### `models.Tool`

```python
value: models.Tool = /* values here */
```

