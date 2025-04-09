"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from atoma_sdk.types import BaseModel
from typing_extensions import TypedDict


class NodesCreateLockRequestTypedDict(TypedDict):
    r"""Request body for creating a node lock"""

    model: str
    r"""The model to lock a node for"""
    max_num_tokens: Optional[int]
    r"""The maximum number of tokens to lock a node for"""
    timeout: Optional[int]
    r"""The timeout for the node lock in milliseconds"""


class NodesCreateLockRequest(BaseModel):
    r"""Request body for creating a node lock"""

    model: str
    r"""The model to lock a node for"""

    max_num_tokens: OptionalNullable[int] = UNSET
    r"""The maximum number of tokens to lock a node for"""

    timeout: OptionalNullable[int] = UNSET
    r"""The timeout for the node lock in milliseconds"""
