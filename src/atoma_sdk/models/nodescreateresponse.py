"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from atoma_sdk.types import BaseModel
from typing_extensions import TypedDict


class NodesCreateResponseTypedDict(TypedDict):
    message: str
    r"""The message of the response"""


class NodesCreateResponse(BaseModel):
    message: str
    r"""The message of the response"""
