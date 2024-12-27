"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from .chatcompletionchunk import ChatCompletionChunk, ChatCompletionChunkTypedDict
from atoma_sdk.types import BaseModel
from typing_extensions import TypedDict


class ChatCompletionStreamResponseTypedDict(TypedDict):
    data: ChatCompletionChunkTypedDict


class ChatCompletionStreamResponse(BaseModel):
    data: ChatCompletionChunk