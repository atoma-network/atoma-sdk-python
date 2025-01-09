"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from atoma_sdk.types import BaseModel
from typing_extensions import TypedDict


class NodePublicAddressAssignmentTypedDict(TypedDict):
    r"""Represents the payload for the node public address registration request.

    This struct represents the payload for the node public address registration request.
    """

    country: str
    r"""The country of the node"""
    node_small_id: int
    r"""Unique small integer identifier for the node"""
    public_address: str
    r"""The public address of the node"""


class NodePublicAddressAssignment(BaseModel):
    r"""Represents the payload for the node public address registration request.

    This struct represents the payload for the node public address registration request.
    """

    country: str
    r"""The country of the node"""

    node_small_id: int
    r"""Unique small integer identifier for the node"""

    public_address: str
    r"""The public address of the node"""
