"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from .nodepublicaddressassignment import (
    NodePublicAddressAssignment,
    NodePublicAddressAssignmentTypedDict,
)
from atoma_sdk.types import BaseModel
from typing_extensions import TypedDict


class NodesCreateRequestTypedDict(TypedDict):
    r"""Represents the payload for the node public address registration request."""

    data: NodePublicAddressAssignmentTypedDict
    r"""Represents the payload for the node public address registration request.

    This struct represents the payload for the node public address registration request.
    """
    signature: str
    r"""The signature of the data base 64 encoded"""


class NodesCreateRequest(BaseModel):
    r"""Represents the payload for the node public address registration request."""

    data: NodePublicAddressAssignment
    r"""Represents the payload for the node public address registration request.

    This struct represents the payload for the node public address registration request.
    """

    signature: str
    r"""The signature of the data base 64 encoded"""