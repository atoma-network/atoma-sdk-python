"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from atoma_sdk.types import BaseModel
from typing_extensions import TypedDict


class NodesCreateLockRequestTypedDict(TypedDict):
    r"""Request body for creating a node lock"""

    model: str
    r"""The model to lock a node for"""


class NodesCreateLockRequest(BaseModel):
    r"""Request body for creating a node lock"""

    model: str
    r"""The model to lock a node for"""