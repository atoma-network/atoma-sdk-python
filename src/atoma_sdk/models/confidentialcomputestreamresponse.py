"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from .confidentialcomputeresponse import (
    ConfidentialComputeResponse,
    ConfidentialComputeResponseTypedDict,
)
from atoma_sdk.types import BaseModel
from typing_extensions import TypedDict


class ConfidentialComputeStreamResponseTypedDict(TypedDict):
    r"""Represents a response from a confidential compute request"""

    data: ConfidentialComputeResponseTypedDict
    r"""Represents a response from a confidential compute request"""


class ConfidentialComputeStreamResponse(BaseModel):
    r"""Represents a response from a confidential compute request"""

    data: ConfidentialComputeResponse
    r"""Represents a response from a confidential compute request"""